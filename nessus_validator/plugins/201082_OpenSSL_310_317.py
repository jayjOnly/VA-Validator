# nessus_validator/plugins/openssl_vulnerability.py

import subprocess
import re
import time

# Tetapkan ID plugin dan informasi
PLUGIN_ID = "201082"
PLUGIN_NAME = "OpenSSL 3.1.0 < 3.1.7 Vulnerability"
DESCRIPTION = "Validasi apakah server menggunakan OpenSSL versi rentan (3.1.0 hingga 3.1.6)"

def get_openssl_version(ip, port):
    """
    Menggunakan curl untuk mendapatkan informasi TLS/SSL dari server dengan timeout adaptif.
    """
    try:
        start_time = time.time()
        result = subprocess.run(
            ["curl", "--max-time", "15", "-v", f"https://{ip}:{port}", "--insecure"],
            capture_output=True, text=True
        )
        elapsed_time = time.time() - start_time
        
        # Jika terlalu lama, anggap gagal agar tidak mengganggu server
        if elapsed_time > 12:
            return "Timeout"
        
        # Cari versi OpenSSL dalam output
        match = re.search(r'OpenSSL/(\d+\.\d+\.\d+)', result.stderr)
        if match:
            return match.group(1)
        
    except subprocess.TimeoutExpired:
        return "Timeout"
    except Exception as e:
        return f"Error: {str(e)}"
    
    return "Unknown"

def get_openssl_version_nmap(ip, port):
    """
    Menggunakan Nmap untuk mendapatkan versi OpenSSL jika curl gagal.
    """
    try:
        result = subprocess.run(
            ["nmap", "-sV", "--script", "ssl-enum-ciphers", "-p", str(port), ip],
            capture_output=True, text=True, timeout=20
        )
        
        # Cari versi OpenSSL dalam output
        match = re.search(r'OpenSSL[\s/]([0-9]+\.[0-9]+\.[0-9]+)', result.stdout)
        if match:
            return match.group(1)
        
    except subprocess.TimeoutExpired:
        return "Timeout"
    except Exception as e:
        return f"Error: {str(e)}"
    
    return "Unknown"

def validate(ip, port):
    """
    Implementasi validasi untuk plugin dengan optimasi agar tidak membebani server.
    
    Args:
        ip: IP Address target
        port: Port target
        
    Returns:
        Dict dengan hasil validasi
    """
    openssl_version = get_openssl_version(ip, port)
    
    # Jika cURL gagal, coba dengan Nmap
    if openssl_version in ["Unknown", "Timeout"]:
        openssl_version = get_openssl_version_nmap(ip, port)
    
    # Periksa apakah versi dalam rentang rentan
    vulnerable_versions = ["3.1.0", "3.1.1", "3.1.2", "3.1.3", "3.1.4", "3.1.5", "3.1.6"]
    is_vulnerable = openssl_version in vulnerable_versions
    
    result = {
        "plugin_id": PLUGIN_ID,
        "plugin_name": PLUGIN_NAME,
        "ip": ip,
        "port": port,
        "openssl_version": openssl_version,
        "vulnerable": is_vulnerable if openssl_version not in ["Unknown", "Timeout"] else None,
        "details": f"Detected OpenSSL version: {openssl_version}",
        "validation_status": "Validated" if openssl_version not in ["Unknown", "Timeout"] else "Failed"
    }
    
    return result