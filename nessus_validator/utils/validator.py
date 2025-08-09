import importlib
import pkgutil
from typing import Dict, Any, List, Optional
import nessus_validator.plugins as plugins

def get_available_plugins() -> Dict[str, str]:
    """
    Mendapatkan daftar semua plugin yang tersedia.
    
    Returns:
        Dict dengan plugin_id sebagai key dan nama modul sebagai value
    """
    available_plugins = {}
    
    # Secara dinamis menemukan semua plugin
    plugin_package = plugins
    for _, name, is_pkg in pkgutil.iter_modules(plugin_package.__path__):
        if not is_pkg and name != "__init__":
            try:
                module = importlib.import_module(f"nessus_validator.plugins.{name}")
                if hasattr(module, "PLUGIN_ID"):
                    available_plugins[module.PLUGIN_ID] = name
            except Exception:
                pass
    
    return available_plugins

def get_plugin_module(plugin_id: str) -> Optional[Any]:
    """
    Mendapatkan modul plugin berdasarkan plugin_id.
    
    Args:
        plugin_id: ID plugin yang dicari
        
    Returns:
        Modul plugin jika ditemukan, None jika tidak
    """
    available_plugins = get_available_plugins()
    
    if plugin_id in available_plugins:
        module_name = available_plugins[plugin_id]
        return importlib.import_module(f"nessus_validator.plugins.{module_name}")
    
    return None

def validate_finding(plugin_id: str, ip: str, port: int) -> Dict[str, Any]:
    """
    Memvalidasi temuan berdasarkan plugin_id.
    
    Args:
        plugin_id: ID plugin yang akan digunakan
        ip: IP Address target
        port: Port target
        
    Returns:
        Dict dengan hasil validasi
    """
    plugin_module = get_plugin_module(plugin_id)
    
    if not plugin_module:
        return {
            "plugin_id": plugin_id,
            "plugin_name": "Unknown Plugin",
            "ip": ip,
            "port": port,
            "vulnerable": "Unknown",
            "details": f"No plugin found for plugin ID: {plugin_id}",
            "validation_status": "Plugin Not Found"
        }
    
    try:
        # Panggil fungsi validate dari modul plugin
        result = plugin_module.validate(ip, port)
        return result
    except Exception as e:
        return {
            "plugin_id": plugin_id,
            "plugin_name": getattr(plugin_module, "PLUGIN_NAME", "Unknown Plugin"),
            "ip": ip,
            "port": port,
            "vulnerable": "Error",
            "details": f"Error during validation: {str(e)}",
            "validation_status": "Error"
        }