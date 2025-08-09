import subprocess
import re
import datetime
from typing import Dict, Any, Optional

PLUGIN_ID = "15901"
PLUGIN_NAME = "SSL Certificate Expiry"
DESCRIPTION = "SSL certificate is expired or will expire soon"

def run_nmap_ssl_cert(ip: str, port: int) -> Optional[str]:
    """
    Menjalankan nmap untuk mendapatkan informasi sertifikat SSL.
    """
    try:
        result = subprocess.run(
            ["nmap", "-p", str(port), "--script", "ssl-cert", ip],
            capture_output=True, text=True, timeout=15
        )
        return result.stdout
    except Exception as e:
        return None

def parse_ssl_expiry(nmap_output: str) -> Optional[datetime.datetime]:
    """
    Mengekstrak tanggal kedaluwarsa sertifikat dari output nmap.
    """
    match = re.search(r'Not valid after:\s*(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', nmap_output)
    if match:
        try:
            return datetime.datetime.strptime(match.group(1), "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            return None
    return None

def validate(ip: str, port: int) -> Dict[str, Any]:
    """
    Mengecek status kedaluwarsa sertifikat SSL menggunakan nmap.
    """
    try:
        nmap_output = run_nmap_ssl_cert(ip, port)
        if not nmap_output:
            return {
                "plugin_id": PLUGIN_ID,
                "plugin_name": PLUGIN_NAME,
                "ip": ip,
                "port": port,
                "vulnerable": "Error",
                "details": "Gagal mendapatkan informasi sertifikat dengan nmap",
                "validation_status": "Error"
            }
        
        expire_date = parse_ssl_expiry(nmap_output)
        if not expire_date:
            return {
                "plugin_id": PLUGIN_ID,
                "plugin_name": PLUGIN_NAME,
                "ip": ip,
                "port": port,
                "vulnerable": "Error",
                "details": "Tidak dapat mengekstrak tanggal kedaluwarsa sertifikat",
                "validation_status": "Error"
            }
        
        days_until_expiry = (expire_date - datetime.datetime.now()).days
        is_expiring_soon = days_until_expiry <= 30
        expire_date_str = expire_date.strftime("%Y-%m-%d")
        
        details = (
            f"Sertifikat SSL akan kedaluwarsa pada {expire_date_str} "
            f"(dalam {days_until_expiry} hari)"
            if days_until_expiry >= 0
            else f"Sertifikat SSL sudah kedaluwarsa pada {expire_date_str} "
                 f"({abs(days_until_expiry)} hari yang lalu)"
        )
        
        return {
            "plugin_id": PLUGIN_ID,
            "plugin_name": PLUGIN_NAME,
            "ip": ip,
            "port": port,
            "vulnerable": is_expiring_soon,
            "details": details,
            "validation_status": "Validated" if is_expiring_soon else "Not Vulnerable"
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

