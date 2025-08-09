import subprocess
import re
import os
import tempfile
from typing import Dict, Any, Tuple, Optional

# Plugin ID dan informasi
PLUGIN_ID = "42873"
PLUGIN_NAME = "SWEET32"
DESCRIPTION = "SSL/TLS connections using 3DES/CBC ciphers are vulnerable to the SWEET32 attack"

def run_nmap_ssl_scan(ip: str, port: int) -> Optional[str]:
    """
    Menjalankan nmap dengan skrip ssl-enum-ciphers untuk memindai kerentanan SSL/TLS.
    
    Args:
        ip: Alamat IP target
        port: Port target
        
    Returns:
        Output dari nmap atau None jika terjadi error
    """
    try:
        # Pastikan port adalah integer
        port = int(port)
        
        # Siapkan perintah nmap
        cmd = [
            "nmap", 
            "--script", "ssl-enum-ciphers", 
            "-p", str(port), 
            "--script-args", "vulns.showall", 
            "-oN", "-",  # Output ke stdout dalam format normal
            ip
        ]
        
        # Jalankan perintah nmap
        process = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60
        )
        
        # Kembalikan output atau pesan error
        return process.stdout if process.returncode == 0 else process.stderr
    
    except Exception as e:
        return None

def check_3des_vulnerability(nmap_output: str) -> Tuple[bool, str]:
    """
    Menganalisis output nmap untuk menemukan kerentanan SWEET32 (3DES).
    
    Args:
        nmap_output: Output dari nmap scan
        
    Returns:
        Tuple (is_vulnerable, vulnerability_details)
    """
    # Cek apakah 3DES disebut dalam output
    has_3des = False
    details = []
    
    # Pattern untuk mencari cipher 3DES
    patterns = [
        r"DES-CBC3-SHA",
        r"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        r"SWEET32",
        r'DES-CBC3',
        r'3DES',
        r'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
        r'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA',
        r'TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA',
        r'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA',
        r'TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA',
        r'SSL_RSA_WITH_3DES_EDE_CBC_SHA'
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, nmap_output, re.IGNORECASE)
        if matches:
            has_3des = True
            details.extend(matches)
    
    # Buat detail kerentanan
    if has_3des:
        vulnerability_details = f"Kerentanan SWEET32 terdeteksi. Cipher yang bermasalah: {', '.join(set(details))}"
    else:
        vulnerability_details = "Tidak ditemukan cipher 3DES yang rentan terhadap SWEET32"
    
    return has_3des, vulnerability_details

def validate(ip: str, port: int) -> Dict[str, Any]:
    """
    Validasi kerentanan SWEET32 pada target menggunakan nmap.
    
    Args:
        ip: IP Address target
        port: Port yang akan divalidasi
        
    Returns:
        Dict dengan hasil validasi
    """
    try:
        # Cek apakah nmap tersedia
        try:
            subprocess.run(["nmap", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        except (subprocess.SubprocessError, FileNotFoundError):
            return {
                "plugin_id": PLUGIN_ID,
                "plugin_name": PLUGIN_NAME,
                "ip": ip,
                "port": port,
                "vulnerable": "Error",
                "details": "Nmap tidak terinstall atau tidak tersedia di PATH",
                "validation_status": "Error"
            }
        
        # Jalankan nmap scan
        nmap_output = run_nmap_ssl_scan(ip, port)
        
        if nmap_output is None:
            return {
                "plugin_id": PLUGIN_ID,
                "plugin_name": PLUGIN_NAME,
                "ip": ip,
                "port": port,
                "vulnerable": "Error",
                "details": "Error saat menjalankan nmap",
                "validation_status": "Error"
            }
        
        # Analisis hasil
        is_vulnerable, vulnerability_details = check_3des_vulnerability(nmap_output)
        
        result = {
            "plugin_id": PLUGIN_ID,
            "plugin_name": PLUGIN_NAME,
            "ip": ip,
            "port": port,
            "vulnerable": is_vulnerable,
            "details": nmap_output,
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