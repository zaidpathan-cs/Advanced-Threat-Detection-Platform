from flask import Flask, request, jsonify, render_template
import os
import json
from datetime import datetime
import hashlib
import time
import requests
from werkzeug.utils import secure_filename
from flask_cors import CORS
from urllib.parse import urlparse
import ipaddress
import socket
import dns.resolver
import whois
import re

app = Flask(__name__)
CORS(app)
app.config['MAX_CONTENT_LENGTH'] = 650 * 1024 * 1024

# In-memory storage for scans
scan_history = []
DNS_RESOLVER = dns.resolver.Resolver()

# Environment variables for API keys (set these in your system)
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')
ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY', '')

def calculate_file_hash(content, hash_type='sha256'):
    """Calculate file hash"""
    if hash_type == 'sha256':
        return hashlib.sha256(content).hexdigest()
    elif hash_type == 'md5':
        return hashlib.md5(content).hexdigest()
    elif hash_type == 'sha1':
        return hashlib.sha1(content).hexdigest()
    return hashlib.sha256(content).hexdigest()

def is_ip_address(input_str):
    """Check if input is an IP address"""
    try:
        ipaddress.ip_address(input_str)
        return True
    except ValueError:
        return False

def resolve_dns(domain):
    """Resolve DNS records for a domain"""
    try:
        records = {
            'A': [],
            'AAAA': [],
            'MX': [],
            'NS': [],
            'TXT': [],
            'CNAME': []
        }
        
        # Get A records (IPv4)
        try:
            answers = DNS_RESOLVER.resolve(domain, 'A')
            records['A'] = [str(r) for r in answers]
        except:
            pass
        
        # Get AAAA records (IPv6)
        try:
            answers = DNS_RESOLVER.resolve(domain, 'AAAA')
            records['AAAA'] = [str(r) for r in answers]
        except:
            pass
        
        # Get MX records
        try:
            answers = DNS_RESOLVER.resolve(domain, 'MX')
            records['MX'] = [str(r.exchange) for r in answers]
        except:
            pass
        
        # Get NS records
        try:
            answers = DNS_RESOLVER.resolve(domain, 'NS')
            records['NS'] = [str(r) for r in answers]
        except:
            pass
        
        # Get TXT records
        try:
            answers = DNS_RESOLVER.resolve(domain, 'TXT')
            records['TXT'] = [str(r) for r in answers]
        except:
            pass
        
        # Get CNAME records
        try:
            answers = DNS_RESOLVER.resolve(domain, 'CNAME')
            records['CNAME'] = [str(r.target) for r in answers]
        except:
            pass
        
        return {
            'success': True,
            'records': records
        }
        
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'records': {}
        }

def check_hash_virustotal(file_hash):
    """Check file hash against VirusTotal"""
    if not VIRUSTOTAL_API_KEY:
        return {'error': 'VirusTotal API key not configured'}
    
    try:
        headers = {'x-apikey': VIRUSTOTAL_API_KEY}
        response = requests.get(
            f'https://www.virustotal.com/api/v3/files/{file_hash}',
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            return {
                'source': 'VirusTotal',
                'found': True,
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0),
                'timeout': stats.get('timeout', 0),
                'total': sum(stats.values())
            }
        elif response.status_code == 404:
            return {'source': 'VirusTotal', 'found': False}
            
    except Exception as e:
        pass
    
    return {'error': 'Failed to check VirusTotal'}

def check_ip_abuseipdb(ip_address):
    """Check IP against AbuseIPDB"""
    if not ABUSEIPDB_API_KEY:
        return {'error': 'AbuseIPDB API key not configured'}
    
    try:
        headers = {'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'}
        params = {'ipAddress': ip_address, 'maxAgeInDays': 90}
        response = requests.get(
            'https://api.abuseipdb.com/api/v2/check',
            headers=headers,
            params=params,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            result = data.get('data', {})
            return {
                'source': 'AbuseIPDB',
                'found': True,
                'abuse_score': result.get('abuseConfidenceScore', 0),
                'reports': result.get('totalReports', 0),
                'country': result.get('countryCode'),
                'isp': result.get('isp'),
                'domain': result.get('domain'),
                'hostnames': result.get('hostnames', []),
                'last_reported': result.get('lastReportedAt')
            }
            
    except Exception as e:
        pass
    
    return {'error': 'Failed to check AbuseIPDB'}

def check_dnsbl(ip_address):
    """Check IP against DNS blacklists"""
    try:
        ip_parts = ip_address.split('.')
        reversed_ip = '.'.join(reversed(ip_parts))
        
        dnsbls = [
            'zen.spamhaus.org',
            'bl.spamcop.net',
            'b.barracudacentral.org',
            'dnsbl.sorbs.net'
        ]
        
        results = []
        for dnsbl in dnsbls:
            try:
                query = f'{reversed_ip}.{dnsbl}'
                socket.gethostbyname(query)
                results.append({'list': dnsbl, 'listed': True})
            except socket.gaierror:
                results.append({'list': dnsbl, 'listed': False})
        
        listed_count = len([r for r in results if r['listed']])
        return {
            'source': 'DNS Blacklists',
            'found': True,
            'results': results,
            'listed_count': listed_count
        }
    except Exception as e:
        return {'error': f'DNSBL check failed: {str(e)}'}

def get_ip_geolocation(ip_address):
    """Get IP geolocation"""
    try:
        response = requests.get(f'https://ipapi.co/{ip_address}/json/', timeout=5)
        if response.status_code == 200:
            data = response.json()
            return {
                'success': True,
                'ip': ip_address,
                'country': data.get('country_name'),
                'country_code': data.get('country_code'),
                'region': data.get('region'),
                'city': data.get('city'),
                'latitude': data.get('latitude'),
                'longitude': data.get('longitude'),
                'org': data.get('org'),
                'asn': data.get('asn')
            }
    except:
        pass
    
    return {'success': False, 'ip': ip_address}

def get_reverse_dns(ip_address):
    """Get reverse DNS for IP"""
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except:
        return None

def get_whois_info(target):
    """Get WHOIS information"""
    try:
        w = whois.whois(target)
        return {
            'success': True,
            'domain_name': w.domain_name,
            'registrar': w.registrar,
            'creation_date': str(w.creation_date[0]) if isinstance(w.creation_date, list) else str(w.creation_date),
            'expiration_date': str(w.expiration_date[0]) if isinstance(w.expiration_date, list) else str(w.expiration_date),
            'updated_date': str(w.updated_date[0]) if isinstance(w.updated_date, list) else str(w.updated_date),
            'name_servers': list(w.name_servers) if w.name_servers else [],
            'status': w.status if w.status else 'Unknown',
            'emails': w.emails if w.emails else []
        }
    except Exception as e:
        return {'success': False, 'error': str(e)}

@app.route('/')
def index():
    """Serve the main page"""
    return render_template('index.html')

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get system statistics"""
    return jsonify({
        'status': 'running',
        'total_scans': len(scan_history),
        'last_scan': scan_history[0]['timestamp'] if scan_history else None,
        'features': {
            'file_scan': VIRUSTOTAL_API_KEY != '',
            'ip_reputation': ABUSEIPDB_API_KEY != '',
            'dns_resolution': True,
            'whois_lookup': True,
            'geolocation': True
        }
    })

@app.route('/api/scan/file', methods=['POST'])
def scan_file():
    """Scan uploaded file"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    try:
        # Read file content
        content = file.read()
        filename = secure_filename(file.filename)
        file_size = len(content)
        
        # Calculate hashes
        sha256_hash = calculate_file_hash(content, 'sha256')
        md5_hash = calculate_file_hash(content, 'md5')
        
        # Check VirusTotal
        vt_result = check_hash_virustotal(sha256_hash)
        
        # Determine status based on VirusTotal results
        malicious_count = vt_result.get('malicious', 0) if isinstance(vt_result, dict) else 0
        
        if malicious_count > 0:
            status = 'malicious'
            status_text = 'MALICIOUS'
        elif vt_result.get('suspicious', 0) > 0:
            status = 'suspicious'
            status_text = 'SUSPICIOUS'
        else:
            status = 'clean'
            status_text = 'CLEAN'
        
        # Create result object
        result = {
            'success': True,
            'type': 'file',
            'filename': filename,
            'size': file_size,
            'hashes': {
                'sha256': sha256_hash,
                'md5': md5_hash
            },
            'vt_check': vt_result,
            'detection': {
                'malicious': malicious_count,
                'suspicious': vt_result.get('suspicious', 0),
                'harmless': vt_result.get('harmless', 0),
                'undetected': vt_result.get('undetected', 0),
                'status': status,
                'status_text': status_text
            },
            'scan_date': datetime.now().isoformat()
        }
        
        # Add to history
        scan_history.insert(0, {
            'id': sha256_hash[:16],
            'input': filename,
            'type': 'file',
            'status': status,
            'timestamp': datetime.now().isoformat(),
            'result': result
        })
        
        # Keep only last 100 scans
        if len(scan_history) > 100:
            scan_history.pop()
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/url', methods=['POST'])
def scan_url():
    """Scan URL"""
    data = request.get_json()
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    # Validate URL format
    if not url.startswith(('http://', 'https://')):
        return jsonify({'error': 'URL must start with http:// or https://'}), 400
    
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        if not domain:
            return jsonify({'error': 'Invalid URL'}), 400
        
        # Get DNS records
        dns_info = resolve_dns(domain)
        
        # Get WHOIS info
        whois_info = get_whois_info(domain)
        
        # Check IP reputation for all A records
        ip_checks = []
        if dns_info.get('success'):
            for ip in dns_info['records'].get('A', []):
                abuse_result = check_ip_abuseipdb(ip)
                dnsbl_result = check_dnsbl(ip)
                geo_info = get_ip_geolocation(ip)
                reverse_dns = get_reverse_dns(ip)
                
                ip_checks.append({
                    'ip': ip,
                    'abuseipdb': abuse_result,
                    'dnsbl': dnsbl_result,
                    'geolocation': geo_info,
                    'reverse_dns': reverse_dns
                })
        
        # Determine if malicious
        malicious_ips = 0
        suspicious_ips = 0
        
        for ip_check in ip_checks:
            abuse_score = ip_check['abuseipdb'].get('abuse_score', 0) if isinstance(ip_check['abuseipdb'], dict) else 0
            listed_count = ip_check['dnsbl'].get('listed_count', 0) if isinstance(ip_check['dnsbl'], dict) else 0
            
            if abuse_score > 70 or listed_count >= 2:
                malicious_ips += 1
            elif abuse_score > 30 or listed_count >= 1:
                suspicious_ips += 1
        
        # Determine overall status
        if malicious_ips > 0:
            status = 'malicious'
            status_text = 'MALICIOUS'
        elif suspicious_ips > 0:
            status = 'suspicious'
            status_text = 'SUSPICIOUS'
        else:
            status = 'clean'
            status_text = 'CLEAN'
        
        # Create result
        result = {
            'success': True,
            'type': 'url',
            'url': url,
            'domain': domain,
            'dns_info': dns_info,
            'whois_info': whois_info,
            'ip_checks': ip_checks,
            'detection': {
                'malicious_ips': malicious_ips,
                'suspicious_ips': suspicious_ips,
                'total_ips_checked': len(ip_checks),
                'status': status,
                'status_text': status_text
            },
            'scan_date': datetime.now().isoformat()
        }
        
        # Add to history
        scan_history.insert(0, {
            'id': hashlib.md5(url.encode()).hexdigest()[:16],
            'input': url,
            'type': 'url',
            'status': status,
            'timestamp': datetime.now().isoformat(),
            'result': result
        })
        
        if len(scan_history) > 100:
            scan_history.pop()
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/ip', methods=['POST'])
def scan_ip():
    """Scan IP address"""
    data = request.get_json()
    ip_address = data.get('ip', '').strip()
    
    if not ip_address:
        return jsonify({'error': 'IP address is required'}), 400
    
    # Validate IP address
    if not is_ip_address(ip_address):
        return jsonify({'error': 'Invalid IP address'}), 400
    
    try:
        ip_obj = ipaddress.ip_address(ip_address)
        
        # Check IP reputation
        abuse_result = check_ip_abuseipdb(ip_address)
        dnsbl_result = check_dnsbl(ip_address)
        geo_info = get_ip_geolocation(ip_address)
        reverse_dns = get_reverse_dns(ip_address)
        whois_info = get_whois_info(ip_address)
        
        # Determine if malicious
        abuse_score = abuse_result.get('abuse_score', 0) if isinstance(abuse_result, dict) else 0
        listed_count = dnsbl_result.get('listed_count', 0) if isinstance(dnsbl_result, dict) else 0
        
        if abuse_score > 70 or listed_count >= 2:
            status = 'malicious'
            status_text = 'MALICIOUS'
        elif abuse_score > 30 or listed_count >= 1:
            status = 'suspicious'
            status_text = 'SUSPICIOUS'
        else:
            status = 'clean'
            status_text = 'CLEAN'
        
        # Create result
        result = {
            'success': True,
            'type': 'ip',
            'ip': ip_address,
            'ip_info': {
                'version': 'IPv4' if ip_obj.version == 4 else 'IPv6',
                'is_private': ip_obj.is_private,
                'is_global': ip_obj.is_global,
                'is_reserved': ip_obj.is_reserved
            },
            'reputation': {
                'abuseipdb': abuse_result,
                'dnsbl': dnsbl_result
            },
            'geolocation': geo_info,
            'reverse_dns': reverse_dns,
            'whois_info': whois_info,
            'detection': {
                'abuse_score': abuse_score,
                'dnsbl_listings': listed_count,
                'status': status,
                'status_text': status_text
            },
            'scan_date': datetime.now().isoformat()
        }
        
        # Add to history
        scan_history.insert(0, {
            'id': hashlib.md5(ip_address.encode()).hexdigest()[:16],
            'input': ip_address,
            'type': 'ip',
            'status': status,
            'timestamp': datetime.now().isoformat(),
            'result': result
        })
        
        if len(scan_history) > 100:
            scan_history.pop()
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/domain', methods=['POST'])
def scan_domain():
    """Scan domain"""
    data = request.get_json()
    domain = data.get('domain', '').strip().lower()
    
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    
    try:
        # Clean domain (remove protocol if present)
        domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
        
        # Get DNS records
        dns_info = resolve_dns(domain)
        
        # Get WHOIS info
        whois_info = get_whois_info(domain)
        
        # Check IP reputation for all A records
        ip_checks = []
        if dns_info.get('success'):
            for ip in dns_info['records'].get('A', []):
                abuse_result = check_ip_abuseipdb(ip)
                dnsbl_result = check_dnsbl(ip)
                
                ip_checks.append({
                    'ip': ip,
                    'abuseipdb': abuse_result,
                    'dnsbl': dnsbl_result
                })
        
        # Determine if malicious
        malicious_ips = 0
        suspicious_ips = 0
        
        for ip_check in ip_checks:
            abuse_score = ip_check['abuseipdb'].get('abuse_score', 0) if isinstance(ip_check['abuseipdb'], dict) else 0
            listed_count = ip_check['dnsbl'].get('listed_count', 0) if isinstance(ip_check['dnsbl'], dict) else 0
            
            if abuse_score > 70 or listed_count >= 2:
                malicious_ips += 1
            elif abuse_score > 30 or listed_count >= 1:
                suspicious_ips += 1
        
        # Determine overall status
        if malicious_ips > 0:
            status = 'malicious'
            status_text = 'MALICIOUS'
        elif suspicious_ips > 0:
            status = 'suspicious'
            status_text = 'SUSPICIOUS'
        else:
            status = 'clean'
            status_text = 'CLEAN'
        
        # Create result
        result = {
            'success': True,
            'type': 'domain',
            'domain': domain,
            'dns_info': dns_info,
            'whois_info': whois_info,
            'ip_checks': ip_checks,
            'detection': {
                'malicious_ips': malicious_ips,
                'suspicious_ips': suspicious_ips,
                'total_ips_checked': len(ip_checks),
                'status': status,
                'status_text': status_text
            },
            'scan_date': datetime.now().isoformat()
        }
        
        # Add to history
        scan_history.insert(0, {
            'id': hashlib.md5(domain.encode()).hexdigest()[:16],
            'input': domain,
            'type': 'domain',
            'status': status,
            'timestamp': datetime.now().isoformat(),
            'result': result
        })
        
        if len(scan_history) > 100:
            scan_history.pop()
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/history', methods=['GET'])
def get_history():
    """Get scan history"""
    return jsonify({
        'scans': scan_history[:50],
        'total': len(scan_history)
    })

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'running',
        'timestamp': datetime.now().isoformat(),
        'features_enabled': {
            'file_scan': VIRUSTOTAL_API_KEY != '',
            'ip_reputation': ABUSEIPDB_API_KEY != ''
        }
    })

if __name__ == '__main__':
    print("🚀 Starting GuardianScan Security Scanner")
    print("📡 API Endpoints:")
    print("   • POST /api/scan/file - Scan uploaded file")
    print("   • POST /api/scan/url - Scan URL")
    print("   • POST /api/scan/ip - Scan IP address")
    print("   • POST /api/scan/domain - Scan domain")
    print("   • GET /api/history - Get scan history")
    print("🌐 Access at: http://localhost:5000")
    print("")
    print("📝 Note: For full functionality, set these environment variables:")
    print("   • VIRUSTOTAL_API_KEY - For VirusTotal file scanning")
    print("   • ABUSEIPDB_API_KEY - For AbuseIPDB IP reputation")
    print("")
    print("🛑 Press Ctrl+C to stop the server")
    
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)
