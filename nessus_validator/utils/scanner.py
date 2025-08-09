import concurrent.futures
from typing import List, Dict, Any
from nessus_validator.utils.validator import validate_finding
import pandas as pd

def validate_findings(df: pd.DataFrame, max_workers: int = 10) -> List[Dict[str, Any]]:
    """
    Memvalidasi semua temuan dari DataFrame input.
    
    Args:
        df: DataFrame dengan data temuan
        max_workers: Jumlah maksimum thread untuk validasi paralel
        
    Returns:
        List hasil validasi
    """
    results = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_row = {
            executor.submit(
                validate_finding, 
                str(row['pluginID']), 
                str(row['IP address']), 
                int(row['port'])
            ): (i, row) for i, row in df.iterrows()
        }
        
        for future in concurrent.futures.as_completed(future_to_row):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                i, row = future_to_row[future]
                results.append({
                    "plugin_id": str(row['pluginID']),
                    "plugin_name": "Error",
                    "ip": str(row['IP address']),
                    "port": int(row['port']),
                    "vulnerable": "Error",
                    "details": f"Error: {str(e)}",
                    "validation_status": "Error"
                })
    
    return results