import subprocess
import json
from typing import Dict, Any

# Plugin ID dan informasi
PLUGIN_ID = "57582"
PLUGIN_NAME = "SSL Self-Signed Certificate"
DESCRIPTION = "The X.509 certificate chain for this service is not signed by a recognized certificate authority"

def check_ssl_self_signed(hostname: str, port: int) -> bool:
    """
    Cek apakah sertifikat server bisa dipercaya menggunakan Nmap.
    """
    try:
        # Jalankan Nmap dengan skrip untuk memeriksa SSL
        command = [
            "nmap",
            "-p", str(port),
            "--script", "ssl-cert",
            "-oX", "-",  # Output dalam format XML
            hostname
        ]
        
        # Menjalankan perintah Nmap
        result = subprocess.run(command, capture_output=True, text=True, check=True)
    
        output = result.stdout
        
        # Cek apakah output mengandung SSL_Self_Signed_Fallback
        return "SSL_Self_Signed_Fallback" in output
    except subprocess.CalledProcessError:
        return False
    except Exception as e:
        return False

def validate(ip: str, port: int) -> Dict[str, Any]:
    """
    Validasi ssl sertifikat bisa dipercaya atau tidak pada target.
    
    Args:
        ip: IP Address target
        port: Port SSL/TLS
        
    Returns:
        Dict dengan hasil validasi
    """
    try:
        is_vulnerable = check_ssl_self_signed(ip, port)
        
        result = {
            "plugin_id": PLUGIN_ID,
            "plugin_name": PLUGIN_NAME,
            "ip": ip,
            "port": port,
            "vulnerable": is_vulnerable,
            "details": f"Target {'mendukung' if is_vulnerable else 'tidak mendukung'} self signed",
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