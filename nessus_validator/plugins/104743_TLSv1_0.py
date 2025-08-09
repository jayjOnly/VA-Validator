import subprocess
import json
from typing import Dict, Any

# Plugin ID dan informasi
PLUGIN_ID = "104743"
PLUGIN_NAME = "TLS Version 1.0 Protocol Detection"
DESCRIPTION = "Server supports TLS protocol version 1.0, which has known security weaknesses"

def check_tls_v1_0_support(hostname: str, port: int) -> bool:
    """
    Cek apakah server mendukung TLS 1.0 menggunakan Nmap.
    """
    try:
        # Jalankan Nmap dengan skrip untuk memeriksa TLS
        command = [
            "nmap",
            "-p", str(port),
            "--script", "ssl-enum-ciphers",
            "-oX", "-",  # Output dalam format XML
            hostname
        ]
        
        # Menjalankan perintah Nmap
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        
        # Parsing output XML untuk mencari dukungan TLS 1.1
        output = result.stdout
        
        # Cek apakah output mengandung TLS 1.1
        return "TLSv1.0" in output
    except subprocess.CalledProcessError:
        return False
    except Exception as e:
        return False

def validate(ip: str, port: int) -> Dict[str, Any]:
    """
    Validasi dukungan TLS 1.0 pada target.
    
    Args:
        ip: IP Address target
        port: Port SSL/TLS
        
    Returns:
        Dict dengan hasil validasi
    """
    try:
        is_vulnerable = check_tls_v1_0_support(ip, port)
        
        result = {
            "plugin_id": PLUGIN_ID,
            "plugin_name": PLUGIN_NAME,
            "ip": ip,
            "port": port,
            "vulnerable": is_vulnerable,
            "details": f"Target {'mendukung' if is_vulnerable else 'tidak mendukung'} protokol TLS versi 1.0 yang sudah tidak direkomendasikan",
            "validation_status": "Validated" if is_vulnerable else "Not Vulnerable"
        }
        
        return result
    except Exception as e:
        return {
            "plugin_id": PLUGIN_ID,
            "plugin_name": PLUGIN_NAME,
            "ip": ip,
            "port": port,
            "vulnerable": "Error",
            "details": f"Error validating: {str(e)}",
            "validation_status": "Error"
        }