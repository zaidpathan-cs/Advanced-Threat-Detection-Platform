from flask import Flask, request, jsonify, render_template
import os
import hashlib
import time
import requests
from werkzeug.utils import secure_filename
from flask_cors import CORS
from urllib.parse import urlparse
import ipaddress
import socket
import dns.resolver
import re
from datetime import datetime

app = Flask(__name__)
CORS(app)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# In-memory storage for scans
scan_history = []
DNS_RESOLVER = dns.resolver.Resolver()

# Configuration - set these as environment variables on GitHub
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

def check_ip_reputation(ip_address):
    """Check IP reputation against public APIs"""
    results = {
        'abuseipdb': None,
        'dnsbl': None,
        'geolocation': None
    }
    
    # Check AbuseIPDB if API key is available
    if ABUSEIPDB_API_KEY:
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
                results['abuseipdb'] = {
                    'abuse_score': result.get('abuseConfidenceScore', 0),
                    'reports': result.get('totalReports', 0),
                    'country': result.get('countryCode'),
                    'isp': result.get('isp'),
                    'domain': result.get('domain'),
                    'last_reported': result.get('lastReportedAt')
                }
        except:
            pass
    
    # Check DNS blacklists
    try:
        ip_parts = ip_address.split('.')
        reversed_ip = '.'.join(reversed(ip_parts))
        
        dnsbls = ['zen.spamhaus.org', 'bl.spamcop.net']
        dnsbl_results = []
        
        for dnsbl in dnsbls:
            try:
                query = f'{reversed_ip}.{dnsbl}'
                socket.gethostbyname(query)
                dnsbl_results.append({'list': dnsbl, 'listed': True})
            except socket.gaierror:
                dnsbl_results.append({'list': dnsbl, 'listed': False})
        
        listed_count = len([r for r in dnsbl_results if r['listed']])
        results['dnsbl'] = {
            'listed_count': listed_count,
            'results': dnsbl_results
        }
    except:
        pass
    
    # Get geolocation
    try:
        response = requests.get(f'https://ipapi.co/{ip_address}/json/', timeout=5)
        if response.status_code == 200:
            data = response.json()
            results['geolocation'] = {
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
    
    return results

def get_reverse_dns(ip_address):
    """Get reverse DNS for IP"""
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except:
        return None

def check_url_safety(url):
    """Check URL safety using public APIs"""
    results = {
        'google_safe_browsing': None,
        'urlscan': None
    }
    
    # Check Google Safe Browsing (simulated - would need API key)
    try:
        # This is a simulation - in production you'd use the actual API
        # Example: Check for known malicious patterns
        malicious_patterns = ['phishing', 'malware', 'spam', 'fraud']
        url_lower = url.lower()
        
        for pattern in malicious_patterns:
            if pattern in url_lower:
                results['google_safe_browsing'] = {
                    'threats': [pattern],
                    'safe': False
                }
                break
        
        if results['google_safe_browsing'] is None:
            results['google_safe_browsing'] = {
                'threats': [],
                'safe': True
            }
    except:
        pass
    
    # Check URLScan.io (public API)
    try:
        domain = urlparse(url).netloc
        response = requests.get(
            f'https://urlscan.io/api/v1/search/?q=domain:{domain}',
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            results['urlscan'] = {
                'results_count': len(data.get('results', [])),
                'has_results': len(data.get('results', [])) > 0
            }
    except:
        pass
    
    return results

@app.route('/')
def index():
    """Serve the main page"""
    return render_template('index.html')

@app.route('/api/scan/file', methods=['POST'])
def scan_file():
    """Scan uploaded file"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    try:
        content = file.read()
        filename = secure_filename(file.filename)
        file_size = len(content)
        
        # Calculate hashes
        sha256_hash = calculate_file_hash(content, 'sha256')
        md5_hash = calculate_file_hash(content, 'md5')
        sha1_hash = calculate_file_hash(content, 'sha1')
        
        # Check VirusTotal if API key is available
        vt_result = None
        if VIRUSTOTAL_API_KEY:
            try:
                headers = {'x-apikey': VIRUSTOTAL_API_KEY}
                response = requests.get(
                    f'https://www.virustotal.com/api/v3/files/{sha256_hash}',
                    headers=headers,
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                    vt_result = {
                        'malicious': stats.get('malicious', 0),
                        'suspicious': stats.get('suspicious', 0),
                        'undetected': stats.get('undetected', 0),
                        'harmless': stats.get('harmless', 0),
                        'timeout': stats.get('timeout', 0),
                        'total': sum(stats.values())
                    }
            except:
                pass
        
        # Determine status
        if vt_result and vt_result['malicious'] > 0:
            status = 'malicious'
            status_text = 'MALICIOUS'
        elif vt_result and vt_result['suspicious'] > 0:
            status = 'suspicious'
            status_text = 'SUSPICIOUS'
        else:
            status = 'clean'
            status_text = 'CLEAN'
        
        # Create result
        result = {
            'success': True,
            'type': 'file',
            'filename': filename,
            'size': file_size,
            'hashes': {
                'sha256': sha256_hash,
                'md5': md5_hash,
                'sha1': sha1_hash
            },
            'virustotal': vt_result,
            'detection': {
                'status': status,
                'status_text': status_text,
                'malicious_count': vt_result['malicious'] if vt_result else 0,
                'suspicious_count': vt_result['suspicious'] if vt_result else 0
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
        url = 'https://' + url
    
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        
        if not domain:
            return jsonify({'error': 'Invalid URL'}), 400
        
        # Get DNS records
        dns_info = resolve_dns(domain)
        
        # Check IP reputation for all A records
        ip_checks = []
        malicious_ips = 0
        suspicious_ips = 0
        
        if dns_info.get('success'):
            for ip in dns_info['records'].get('A', []):
                reputation = check_ip_reputation(ip)
                reverse_dns = get_reverse_dns(ip)
                
                ip_check = {
                    'ip': ip,
                    'reputation': reputation,
                    'reverse_dns': reverse_dns
                }
                ip_checks.append(ip_check)
                
                # Check if malicious
                abuse_score = reputation['abuseipdb']['abuse_score'] if reputation['abuseipdb'] else 0
                listed_count = reputation['dnsbl']['listed_count'] if reputation['dnsbl'] else 0
                
                if abuse_score > 70 or listed_count >= 2:
                    malicious_ips += 1
                elif abuse_score > 30 or listed_count >= 1:
                    suspicious_ips += 1
        
        # Check URL safety
        url_safety = check_url_safety(url)
        
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
            'ip_checks': ip_checks,
            'url_safety': url_safety,
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
        
        # Get IP reputation
        reputation = check_ip_reputation(ip_address)
        reverse_dns = get_reverse_dns(ip_address)
        
        # Determine if malicious
        abuse_score = reputation['abuseipdb']['abuse_score'] if reputation['abuseipdb'] else 0
        listed_count = reputation['dnsbl']['listed_count'] if reputation['dnsbl'] else 0
        
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
            'reputation': reputation,
            'reverse_dns': reverse_dns,
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
        
        # Check IP reputation for all A records
        ip_checks = []
        malicious_ips = 0
        suspicious_ips = 0
        
        if dns_info.get('success'):
            for ip in dns_info['records'].get('A', []):
                reputation = check_ip_reputation(ip)
                reverse_dns = get_reverse_dns(ip)
                
                ip_check = {
                    'ip': ip,
                    'reputation': reputation,
                    'reverse_dns': reverse_dns
                }
                ip_checks.append(ip_check)
                
                # Check if malicious
                abuse_score = reputation['abuseipdb']['abuse_score'] if reputation['abuseipdb'] else 0
                listed_count = reputation['dnsbl']['listed_count'] if reputation['dnsbl'] else 0
                
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
        'features': {
            'file_scan': VIRUSTOTAL_API_KEY != '',
            'ip_reputation': ABUSEIPDB_API_KEY != '',
            'dns_resolution': True,
            'url_safety': True
        }
    })

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get system statistics"""
    total_scans = len(scan_history)
    malicious = sum(1 for scan in scan_history if scan.get('status') == 'malicious')
    suspicious = sum(1 for scan in scan_history if scan.get('status') == 'suspicious')
    clean = total_scans - malicious - suspicious
    
    return jsonify({
        'total_scans': total_scans,
        'malicious': malicious,
        'suspicious': suspicious,
        'clean': clean,
        'features_enabled': {
            'virustotal': VIRUSTOTAL_API_KEY != '',
            'abuseipdb': ABUSEIPDB_API_KEY != ''
        }
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
