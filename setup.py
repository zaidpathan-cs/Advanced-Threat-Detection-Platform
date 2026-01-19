#!/usr/bin/env python3
"""
VT Clone Setup Script
"""

import os
import sys
import subprocess
import platform

def print_banner():
    banner = """
╔══════════════════════════════════════════════════════════╗
║                  VT CLONE SETUP                          ║
║        Advanced VirusTotal Clone with Real Scanning      ║
╚══════════════════════════════════════════════════════════╝
"""
    print(banner)

def check_python():
    """Check Python version"""
    print("Checking Python version...")
    if sys.version_info < (3, 7):
        print("❌ Python 3.7 or higher is required")
        sys.exit(1)
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor} detected")

def create_directory_structure():
    """Create necessary directories"""
    print("\nCreating directory structure...")
    
    directories = [
        'uploads',
        'static/assets',
        'templates'
    ]
    
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print(f"  Created: {directory}/")
        else:
            print(f"  Exists: {directory}/")
    
    print("✅ Directory structure created")

def create_requirements_file():
    """Create requirements.txt"""
    print("\nCreating requirements.txt...")
    
    requirements = """Flask==2.3.3
Flask-CORS==4.0.0
requests==2.31.0
Werkzeug==2.3.7
python-dotenv==1.0.0
"""
    
    with open('requirements.txt', 'w') as f:
        f.write(requirements)
    
    print("✅ requirements.txt created")

def create_env_file():
    """Create .env file"""
    print("\nCreating .env file...")
    
    env_content = """# VirusTotal API Key (Optional)
# Get one from: https://www.virustotal.com/gui/join-us
VT_API_KEY=

# Flask Secret Key
SECRET_KEY=vt-clone-secret-key-change-in-production

# Debug Mode
FLASK_DEBUG=True

# Upload Configuration
MAX_CONTENT_LENGTH=681574400  # 650MB in bytes
"""
    
    if not os.path.exists('.env'):
        with open('.env', 'w') as f:
            f.write(env_content)
        print("✅ .env file created")
    else:
        print("⚠️  .env file already exists")

def install_dependencies():
    """Install Python dependencies"""
    print("\nInstalling dependencies...")
    
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'])
        print("✅ Dependencies installed successfully")
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        print("You can manually install with: pip install -r requirements.txt")

def install_optional_dependencies():
    """Install optional dependencies for advanced features"""
    print("\nInstalling optional dependencies...")
    
    optional_packages = [
        'python-magic-bin' if platform.system() == 'Windows' else 'python-magic',
        'pefile',
        'yara-python'
    ]
    
    for package in optional_packages:
        try:
            print(f"Installing {package}...")
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
            print(f"✅ {package} installed")
        except subprocess.CalledProcessError:
            print(f"⚠️  Failed to install {package} (optional)")

def create_run_scripts():
    """Create run scripts for different platforms"""
    print("\nCreating run scripts...")
    
    # Windows batch file
    if platform.system() == 'Windows':
        with open('run.bat', 'w') as f:
            f.write("""@echo off
echo Starting VT Clone...
echo.
python app.py
pause
""")
        print("✅ Created run.bat")
    
    # Unix shell script
    with open('run.sh', 'w') as f:
        f.write("""#!/bin/bash
echo "Starting VT Clone..."
python3 app.py
""")
    
    os.chmod('run.sh', 0o755)
    print("✅ Created run.sh")

def print_next_steps():
    """Print next steps for the user"""
    print("\n" + "="*60)
    print("SETUP COMPLETE!")
    print("="*60)
    print("\nNext steps:")
    print("1. Get a VirusTotal API key (optional):")
    print("   https://www.virustotal.com/gui/join-us")
    print("\n2. Add your API key to the .env file:")
    print("   VT_API_KEY=your_api_key_here")
    print("\n3. Run the application:")
    if platform.system() == 'Windows':
        print("   Double-click run.bat")
        print("   OR")
        print("   python app.py")
    else:
        print("   ./run.sh")
        print("   OR")
        print("   python3 app.py")
    print("\n4. Open your browser and go to:")
    print("   http://localhost:5000")
    print("\n" + "="*60)

def main():
    print_banner()
    check_python()
    create_directory_structure()
    create_requirements_file()
    create_env_file()
    install_dependencies()
    install_optional_dependencies()
    create_run_scripts()
    print_next_steps()

if __name__ == '__main__':
    main()