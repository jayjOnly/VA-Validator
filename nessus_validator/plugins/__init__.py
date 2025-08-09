"""
Package plugins - Berisi implementasi plugin validator untuk berbagai ID plugin Nessus.

Setiap modul dalam package ini harus mengekspos:
- PLUGIN_ID (str): ID plugin Nessus
- PLUGIN_NAME (str): Nama plugin
- DESCRIPTION (str): Deskripsi plugin
- validate(ip, port) -> dict: Fungsi validasi yang mengembalikan hasil validasi
"""

# Plugin yang tersedia
__all__ = [
    'sweet32_42873'
]