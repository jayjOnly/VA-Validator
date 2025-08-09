import pandas as pd
from typing import List, Dict, Any
import os

def read_input_csv(file_path: str) -> pd.DataFrame:
    """
    Membaca file CSV input dan mengembalikan DataFrame.
    
    Args:
        file_path: Path ke file CSV
        
    Returns:
        DataFrame dengan data dari CSV
    """
    try:
        df = pd.read_csv(file_path)
        required_columns = ['pluginID', 'IP address', 'port']
        
        # Validasi kolom yang diperlukan
        for col in required_columns:
            if col not in df.columns:
                raise ValueError(f"Kolom yang diperlukan '{col}' tidak ditemukan di CSV")
        
        return df
    except Exception as e:
        raise ValueError(f"Error membaca CSV: {str(e)}")

def write_output_csv(results: List[Dict[str, Any]], output_file: str) -> str:
    """
    Menulis hasil validasi ke file CSV output.
    
    Args:
        results: List hasil validasi
        output_file: Path ke file output
        
    Returns:
        Path ke file output yang telah dibuat
    """
    try:
        df = pd.DataFrame(results)
        
        # Mapping kolom sesuai format yang diminta
        df_output = pd.DataFrame({
            'pluginID': df['plugin_id'],
            'IP address': df['ip'],
            'port': df['port'],
            'validation_status': df['validation_status'],
            'details': df['details']
        })
        
        # Buat direktori output jika belum ada
        output_dir = os.path.dirname(output_file)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        df_output.to_csv(output_file, index=False)
        return output_file
    except Exception as e:
        raise ValueError(f"Error menulis CSV output: {str(e)}")