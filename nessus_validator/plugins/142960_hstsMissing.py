import subprocess
import json
from typing import Dict, Any

# Plugin ID dan informasi
PLUGIN_ID = "142960"
PLUGIN_NAME = "HSTS Missing From HTTPS Server"
DESCRIPTION = "HTTPS server is missing HTTP Strict Transport Security (HSTS) header as defined in RFC 6797"

def validate(ip: str, port: int) -> Dict[str, Any]:
    """
    Menggunakan nmap untuk memeriksa apakah HSTS diterapkan di server HTTPS target.
    
    Args:
        ip: IP Address atau hostname target
        port: Port HTTPS
    
    Returns:
        Dict dengan hasil validasi
    """
    try:
        # Jalankan nmap dengan script http-security-headers
        cmd = [
            "nmap", "-p", str(port), "--script", "http-security-headers", "--script-args", "http-security-headers.mode=table", ip
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        output = result.stdout
        
        # Cek apakah Strict-Transport-Security ada dalam output
        has_hsts = "Strict-Transport-Security" in output
        
        details = ""
        if has_hsts:
            details = "HTTPS server mengimplementasikan HSTS."
        else:
            details = "HTTPS server tidak mengimplementasikan HTTP Strict Transport Security (HSTS)."
        
        return {
            "plugin_id": PLUGIN_ID,
            "plugin_name": PLUGIN_NAME,
            "ip": ip,
            "port": port,
            "vulnerable": not has_hsts,
            "details": details,
            "validation_status": "Validated" if not has_hsts else "Not Vulnerable"
        }
    
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
