import subprocess
import re
from typing import Dict, Any, Optional, Tuple

# Plugin ID and information
PLUGIN_ID = "57608"
PLUGIN_NAME = "SMB Signing Not Required"
DESCRIPTION = "Signing is not required on the remote SMB server, which could allow man-in-the-middle attacks"

def check_smb_signing(hostname: str, port: int = 445) -> Tuple[bool, str]:
    """
    Check if SMB signing is required on the target server using nmap.
    
    Args:
        hostname: IP Address or hostname of target
        port: SMB port (default is 445)
        
    Returns:
        Tuple containing (is_vulnerable, details)
    """
    try:
        # Run nmap with smb2-security-mode script
        cmd = [
            "nmap", 
            "-p", str(port), 
            "--script", "smb2-security-mode", 
            hostname
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        output = result.stdout
        
        # Check if signing is not required
        signing_disabled = re.search(r"message\s+signing\s+disabled", output, re.IGNORECASE)
        signing_not_required = re.search(r"message\s+signing\s+enabled\s+but\s+not\s+required", output, re.IGNORECASE)
        
        if signing_disabled or signing_not_required:
            return True, output
        else:
            return False, output
            
    except Exception as e:
        return False, f"Error checking SMB signing: {str(e)}"

def validate(ip: str, port: int = 445) -> Dict[str, Any]:
    """
    Validate if SMB signing is not required on the target.
    
    Args:
        ip: IP Address of target
        port: SMB port (default is 445)
        
    Returns:
        Dict with validation results
    """
    try:
        # Check if nmap is available
        try:
            subprocess.run(["nmap", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        except (subprocess.SubprocessError, FileNotFoundError):
            return {
                "plugin_id": PLUGIN_ID,
                "plugin_name": PLUGIN_NAME,
                "ip": ip,
                "port": port,
                "vulnerable": "Error",
                "details": "Nmap is not installed or not available in PATH",
                "validation_status": "Error"
            }
        
        # Check SMB signing
        is_vulnerable, details = check_smb_signing(ip, port)
        
        result = {
            "plugin_id": PLUGIN_ID,
            "plugin_name": PLUGIN_NAME,
            "ip": ip,
            "port": port,
            "vulnerable": is_vulnerable,
            "details": f"Target {'does not require' if is_vulnerable else 'requires'} SMB signing\n\n=== SCAN DETAILS ===\n{details}",
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