import socket
import ssl
import re
from typing import Dict, Any, Tuple, List, Optional

# Plugin ID dan informasi
PLUGIN_ID = "11213"
PLUGIN_NAME = "HTTP TRACE / TRACK Methods Allowed"
DESCRIPTION = "Server allows HTTP TRACE/TRACK methods which can lead to cross-site tracing attacks"

def check_http_method(hostname: str, port: int, method: str, use_ssl: bool = False) -> Tuple[bool, Optional[str]]:
    """
    Cek apakah metode HTTP tertentu diizinkan pada server.
    
    Args:
        hostname: Hostname atau IP target
        port: Port HTTP/HTTPS
        method: Metode HTTP yang akan dicek (TRACE, TRACK)
        use_ssl: True jika menggunakan HTTPS
    
    Returns:
        Tuple (is_allowed, response_headers)
    """
    try:
        # Buat socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        
        # Koneksi ke target
        sock.connect((hostname, port))
        
        # Wrap dengan SSL jika perlu
        if use_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=hostname)
        
        # Buat HTTP request untuk metode yang ditentukan
        request = f"{method} / HTTP/1.1\r\n"
        request += f"Host: {hostname}\r\n"
        request += "Connection: close\r\n"
        request += "\r\n"
        
        # Kirim request
        sock.sendall(request.encode())
        
        # Terima response
        response = b""
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data
        
        sock.close()
        
        # Decode response
        response_str = response.decode('utf-8', errors='ignore')
        
        # Cek jika server mengizinkan metode
        # Kode status 200 OK menunjukkan metode diizinkan
        # Beberapa server mungkin mengembalikan 405 Method Not Allowed jika tidak didukung
        if re.search(r"HTTP/1\.[01]\s+200", response_str):
            return True, response_str
        else:
            return False, response_str
            
    except Exception as e:
        return False, None

def validate(ip: str, port: int) -> Dict[str, Any]:
    """
    Validasi kerentanan HTTP TRACE/TRACK Methods pada target.
    
    Args:
        ip: IP Address atau hostname target
        port: Port HTTP/HTTPS
        
    Returns:
        Dict dengan hasil validasi
    """
    try:
        # Tentukan jika koneksi menggunakan SSL berdasarkan port
        use_ssl = port in [443, 8443]
        
        # Cek metode TRACE
        trace_allowed, trace_response = check_http_method(ip, port, "TRACE", use_ssl)
        
        # Cek metode TRACK (varian Microsoft dari TRACE)
        track_allowed, track_response = check_http_method(ip, port, "TRACK", use_ssl)
        
        # Target rentan jika salah satu metode diizinkan
        is_vulnerable = trace_allowed or track_allowed
        
        # Detail metode yang diizinkan
        allowed_methods = []
        if trace_allowed:
            allowed_methods.append("TRACE")
        if track_allowed:
            allowed_methods.append("TRACK")
        
        methods_str = ", ".join(allowed_methods) if allowed_methods else "None"
        
        result = {
            "plugin_id": PLUGIN_ID,
            "plugin_name": PLUGIN_NAME,
            "ip": ip,
            "port": port,
            "vulnerable": is_vulnerable,
            "details": f"Target {'mengizinkan' if is_vulnerable else 'tidak mengizinkan'} "
                      f"metode HTTP berbahaya: {methods_str}",
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