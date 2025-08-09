import click
import os
import sys
from typing import List, Dict, Any
import pandas as pd
from colorama import init, Fore, Style
from nessus_validator.utils.csv_handler import read_input_csv, write_output_csv
from nessus_validator.utils.scanner import validate_findings
from nessus_validator.utils.validator import get_available_plugins

# Inisialisasi colorama
init()

@click.group()
def cli():
    """Nessus Vulnerability Findings Validator CLI"""
    pass

@cli.command()
@click.option('--input-file', '-i', required=True, help='Path ke file CSV input')
@click.option('--output-file', '-o', default='validation_results.csv', help='Path ke file CSV output')
@click.option('--workers', '-w', default=10, help='Jumlah thread untuk validasi paralel')
def validate(input_file, output_file, workers):
    """Validasi temuan dari file CSV input"""
    try:
        click.echo(f"{Fore.BLUE}[*] Membaca file input: {input_file}{Style.RESET_ALL}")
        df = read_input_csv(input_file)
        
        click.echo(f"{Fore.BLUE}[*] Ditemukan {len(df)} temuan untuk divalidasi{Style.RESET_ALL}")
        
        click.echo(f"{Fore.BLUE}[*] Memulai validasi dengan {workers} thread...{Style.RESET_ALL}")
        results = validate_findings(df, max_workers=workers)
        
        click.echo(f"{Fore.BLUE}[*] Menulis hasil ke: {output_file}{Style.RESET_ALL}")
        output_path = write_output_csv(results, output_file)
        
        # Menampilkan ringkasan
        summary = pd.DataFrame(results)
        # click.echo(f"{results}")
        validated_count = sum(summary['validation_status'] == 'Validated')
        not_vulnerable_count = sum(summary['validation_status'] == 'Not Vulnerable')
        error_count = sum(summary['validation_status'].str.contains('Error'))
        not_found_count = sum(summary['validation_status'] == 'Plugin Not Found')
        
        click.echo(f"\n{Fore.GREEN}[+] Validasi selesai!{Style.RESET_ALL}")
        click.echo(f"{Fore.GREEN}[+] Total temuan: {len(results)}{Style.RESET_ALL}")
        click.echo(f"{Fore.GREEN}[+] Tervalidasi: {validated_count}{Style.RESET_ALL}")
        click.echo(f"{Fore.GREEN}[+] Tidak rentan: {not_vulnerable_count}{Style.RESET_ALL}")
        click.echo(f"{Fore.YELLOW}[!] Plugin tidak ditemukan: {not_found_count}{Style.RESET_ALL}")
        click.echo(f"{Fore.RED}[-] Error: {error_count}{Style.RESET_ALL}")
        click.echo(f"\n{Fore.GREEN}[+] Hasil disimpan di: {output_path}{Style.RESET_ALL}")
        
    except Exception as e:
        click.echo(f"{Fore.RED}[-] Error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)

@cli.command()
def list_plugins():
    """Tampilkan daftar plugin yang tersedia"""
    plugins = get_available_plugins()
    
    if not plugins:
        click.echo(f"{Fore.YELLOW}[!] Tidak ada plugin yang tersedia.{Style.RESET_ALL}")
        return
    
    click.echo(f"{Fore.GREEN}[+] Plugin yang tersedia:{Style.RESET_ALL}")
    for plugin_id, name in plugins.items():
        click.echo(f"  - {Fore.CYAN}ID: {plugin_id}{Style.RESET_ALL}, Module: {name}")

def main():
    """
    Fungsi main untuk entrypoint CLI
    """
    try:
        cli()
    except Exception as e:
        click.echo(f"{Fore.RED}[-] Error tidak terduga: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()