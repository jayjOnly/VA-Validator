# Nessus Validator

Tool untuk memvalidasi temuan vulnerability assessment menggunakan Plugin ID.

## Instalasi

```bash
# Clone repository
git clone https://github.com/jayjOnly/VA-Validator.git
cd nessus-validator

# Install package
pip install -e .
```

## Penggunaan

### Validasi temuan dari file CSV

```bash
nessus-validator validate --input-file input.csv --output-file results.csv
```

Format CSV input harus memiliki kolom berikut:
- `pluginID`: ID plugin Nessus
- `IP address`: Alamat IP target
- `port`: Port target

### Melihat daftar plugin tersedia

```bash
nessus-validator list-plugins
```

## Menambahkan Plugin Baru

Untuk menambahkan plugin baru, cukup buat file Python baru di direktori `nessus_validator/plugins/` dengan format berikut:

```python
# nessus_validator/plugins/nama_plugin.py

# Tetapkan ID plugin dan informasi
PLUGIN_ID = "12345"
PLUGIN_NAME = "Nama Plugin"
DESCRIPTION = "Deskripsi plugin"

def validate(ip, port):
    """
    Implementasi validasi untuk plugin.
    
    Args:
        ip: IP Address target
        port: Port target
        
    Returns:
        Dict dengan hasil validasi
    """
    # Kode validasi Anda di sini
    result = {
        "plugin_id": PLUGIN_ID,
        "plugin_name": PLUGIN_NAME,
        "ip": ip,
        "port": port,
        "vulnerable": True/False,  # Ganti dengan hasil validasi
        "details": "Detail hasil validasi",
        "validation_status": "Validated"  # Atau status lainnya
    }
    
    return result
```

## Contoh CSV Input

```csv
pluginID,IP address,port
42873,192.168.1.1,443
42873,192.168.1.2,8443
```

## Contoh CSV Output

```csv
pluginID,IP address,port,validation_status
42873,192.168.1.1,443,Validated
42873,192.168.1.2,8443,Not Vulnerable
```