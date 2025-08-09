#!/usr/bin/env python3
import subprocess
import re
import json
import sys
from typing import Dict, Any, Tuple, List, Optional

# Plugin ID dan informasi
PLUGIN_ID = "161181"
PLUGIN_NAME = "Apache Tomcat 8.5.0 < 8.5.76 Vulnerability"
DESCRIPTION = "Apache Tomcat versions from 8.5.0 to 8.5.75 are vulnerable"

def check_tomcat_version(hostname: str, port: int) -> Dict[str, Any]:
    """
    Menggunakan Nmap untuk memeriksa versi dan header Apache Tomcat.
    
    Args:
        hostname: Hostname atau IP target
        port: Port HTTP/HTTPS
    
    Returns:
        Dictionary dengan hasil pemeriksaan
    """
    try:
        # Tentukan protokol berdasarkan port
        protocol = "https" if port in [443, 8443] else "http"
        
        # Jalankan nmap dengan script http-headers dan http-title
        cmd = [
            "nmap", 
            "-p", str(port), 
            "-sV", 
            "--script=http-headers,http-title", 
            hostname
        ]
        
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        
        output = stdout.decode('utf-8', errors='ignore')
        
        # Ekstrak informasi versi dari output
        version_match = re.search(r"Apache Tomcat/(\d+\.\d+\.\d+)", output, re.IGNORECASE)
        tomcat_version = version_match.group(1) if version_match else "Unknown"
        
        # Cek apakah versi rentan
        is_vulnerable = False
        if version_match:
            # Parse versi 
            major, minor, patch = map(int, tomcat_version.split('.'))
            
            # Kriteria kerentanan: Tomcat 8.5.0 sampai 8.5.75
            if (major == 8 and minor == 5 and 0 <= patch <= 75):
                is_vulnerable = True
        
        # Ekstrak header server
        server_header_match = re.search(r"Server:\s*(.+)", output)
        server_header = server_header_match.group(1) if server_header_match else "Not Found"
        
        # Ekstrak judul halaman
        title_match = re.search(r"http-title:\s*(.+)", output)
        page_title = title_match.group(1) if title_match else "Not Found"
        
        result = {
            "plugin_id": PLUGIN_ID,
            "plugin_name": PLUGIN_NAME,
            "ip": hostname,
            "port": port,
            "vulnerable": is_vulnerable,
            "tomcat_version": tomcat_version,
            "details": f"Apache Tomcat versi {tomcat_version} "
                       f"{'rentan' if is_vulnerable else 'tidak rentan'} "
                       f"terhadap kerentanan versi 8.5.76",
            "server_header": server_header,
            "page_title": page_title,
            "raw_output": output,
            "validation_status": "Validated" if is_vulnerable else "Not Vulnerable"
        }
        
        return result
    except Exception as e:
        return {
            "plugin_id": PLUGIN_ID,
            "plugin_name": PLUGIN_NAME,
            "ip": hostname,
            "port": port,
            "vulnerable": "Error",
            "details": f"Error validating: {str(e)}",
            "validation_status": "Error"
        }

def validate(ip: str, port: int) -> Dict[str, Any]:
    """
    Validasi kerentanan Apache Tomcat.
    
    Args:
        ip: IP Address atau hostname target
        port: Port HTTP/HTTPS
        
    Returns:
        Dict dengan hasil validasi
    """
    return check_tomcat_version(ip, port)