# nessus_validator/plugins/php_version_checker.py

# Tetapkan ID plugin dan informasi
PLUGIN_ID = "193283"
PLUGIN_NAME = "PHP Version Validator 8.1.x < 8.1.28"
DESCRIPTION = "Validates PHP version to check for vulnerabilities."

import requests
import re

def validate(ip, port=80):
    """
    Implementasi validasi untuk plugin.
    
    Args:
        ip: IP Address target
        port: Port target
        
    Returns:
        Dict dengan hasil validasi
    """
    url = f"http://{ip}:{port}"
    try:
        response = requests.get(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
        headers = response.headers.get("Server", "")
        
        vulnerable = False
        details = "PHP version not found."
        
        # Cari versi PHP langsung dari header Server
        match = re.search(r'PHP/(\d+\.\d+\.\d+)', headers)
        if match:
            version = match.group(1)
            details = f"PHP version detected: {version}"
            vulnerable = version < "8.1.28"  # Sesuaikan logika deteksi
        
        result = {
            "plugin_id": PLUGIN_ID,
            "plugin_name": PLUGIN_NAME,
            "ip": ip,
            "port": port,
            "vulnerable": vulnerable,
            "details": details,
            "validation_status": "Validated"
        }
    
    except requests.exceptions.RequestException as e:
        result = {
            "plugin_id": PLUGIN_ID,
            "plugin_name": PLUGIN_NAME,
            "ip": ip,
            "port": port,
            "vulnerable": False,
            "details": f"Failed to connect: {e}",
            "validation_status": "Error"
        }
    
    return result