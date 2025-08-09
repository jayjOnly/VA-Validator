import subprocess
import re
from typing import Dict, Any

PLUGIN_ID = "10114"
PLUGIN_NAME = "ICMP Timestamp Request Remote Date Disclosure"
DESCRIPTION = "Target responds to ICMP timestamp requests, potentially disclosing system time"

def check_icmp_timestamp(ip: str) -> bool:
    """
    Mengecek apakah target merespons ICMP timestamp request menggunakan ping dengan opsi tsonly.
    """
    try:
        result = subprocess.run(["ping", "-tsonly", "-c", "1", ip], capture_output=True, text=True, timeout=5)
        
        # Cari timestamp dalam output
        if re.search(r'ts_reply', result.stdout):
            return True
        return False
    except Exception as e:
        return False

def validate(ip: str, port: int = 0) -> Dict[str, Any]:
    """
    Validasi kerentanan ICMP Timestamp Request pada target.
    
    Args:
        ip: IP Address target
        port: Tidak digunakan untuk ICMP (disertakan untuk kompatibilitas)
        
    Returns:
        Dict dengan hasil validasi
    """
    try:
        is_vulnerable = check_icmp_timestamp(ip)
        
        result = {
            "plugin_id": PLUGIN_ID,
            "plugin_name": PLUGIN_NAME,
            "ip": ip,
            "port": "N/A",  # ICMP tidak menggunakan port
            "vulnerable": is_vulnerable,
            "details": f"Target {'merespon' if is_vulnerable else 'tidak merespon'} ICMP timestamp requests, "
                      f"{'potentially disclosing system time' if is_vulnerable else ''}",
            "validation_status": "Validated" if is_vulnerable else "Not Vulnerable"
        }
        
        return result
    except Exception as e:
        return {
            "plugin_id": PLUGIN_ID,
            "plugin_name": PLUGIN_NAME,
            "ip": ip,
            "port": "N/A",
            "vulnerable": "Error",
            "details": f"Error validating: {str(e)}",
            "validation_status": "Error"
        }
