#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import requests
import time
import sys
import json
from rich.console import Console
from rich.table import Table
from rich import box
from typing import List, Dict

console = Console()

# === AccessFuzz Banner ===
def print_banner():
    banner = r"""
            █████╗  ██████╗ ██████╗███████╗███████╗███████╗
            ██╔══██╗██╔════╝██╔════╝██╔════╝██╔════╝██╔════╝
            ███████║██║     ██║     █████╗  ███████╗███████╗
            ██╔══██║██║     ██║     ██╔══╝  ╚════██║╚════██║
            ██║  ██║╚██████╗╚██████╗███████╗███████║███████║
            ╚═╝  ╚═╝ ╚═════╝ ╚═════╝╚══════╝╚══════╝╚══════╝
                                                            
            ███████╗██╗   ██╗███████╗███████╗               
            ██╔════╝██║   ██║╚══███╔╝╚══███╔╝               
            █████╗  ██║   ██║  ███╔╝   ███╔╝                
            ██╔══╝  ██║   ██║ ███╔╝   ███╔╝                 
            ██║     ╚██████╔╝███████╗███████╗               
            ╚═╝      ╚═════╝ ╚══════╝╚══════╝               
                                       v0.1 
               github.com/aswinmguptha/accessfuzz
"""
    print(banner)

def load_json(file_path: str):
    try:
        with open(file_path, "r") as f:
            return json.load(f)
    except Exception as e:
        console.print(f"[red]Error loading {file_path}:[/red] {e}")
        return None

def validate_roles(role_tokens: Dict[str, Dict]) -> bool:
    if not isinstance(role_tokens, dict):
        console.print("[red]Error:[/red] Role-token mapping must be a JSON object with role names as keys.")
        return False
    for role, headers in role_tokens.items():
        if not isinstance(headers, dict):
            console.print(f"[red]Error:[/red] Headers for role '{role}' must be a dictionary.")
            return False
    return True

def test_endpoint(endpoint, role, token_headers):
    method = endpoint["method"].upper()
    url = endpoint["url"]
    headers = {**endpoint.get("headers", {}), **token_headers}
    params = endpoint.get("params", {})
    data = endpoint.get("data", None)

    try:
        resp = requests.request(method, url, headers=headers, params=params, json=data, timeout=5)
        return resp.status_code, resp.text
    except Exception as e:
        return 0, str(e)

def run_tests(endpoints: List[Dict], roles: Dict[str, Dict]):
    results = []
    table = Table(show_header=True, header_style="bold magenta", box=box.SIMPLE)
    table.add_column("Method", width=6)
    table.add_column("Endpoint")
    table.add_column("Role", style="cyan", width=10)
    table.add_column("Status", justify="center")
    
    for ep in endpoints:
        method = ep.get("method", "GET")
        url = ep.get("url", "")
        for role, headers in roles.items():
            status_code, _ = test_endpoint(ep, role, headers)
            status_color = "green" if status_code == 200 else "yellow" if status_code in [401, 403] else "red"
            table.add_row(method, url, role, f"[{status_color}]{status_code}[/{status_color}]")
            results.append({
                "method": method,
                "endpoint": url,
                "role": role,
                "status": status_code
            })
            time.sleep(0.2)
    
    console.print("\n[bold underline]Scan Results[/bold underline]")
    console.print(table)
    return results

def write_report(results: List[Dict], output_path: str):
    if not output_path.lower().endswith('.json'):
        output_path += '.json'
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    console.print(f"\n[green]Report saved to:[/green] {output_path}")
    
def main():
    print_banner()
    
    parser = argparse.ArgumentParser(description="AccessFuzz - API Authorization Tester")
    parser.add_argument("--endpoints", required=True, help="Path to JSON file with API endpoints")
    parser.add_argument("--tokens", required=True, help="Path to JSON file with role-token headers")
    parser.add_argument("--output", help="Path to save report JSON", default="accessfuzz_report.json")
    args = parser.parse_args()

    endpoints = load_json(args.endpoints)
    role_tokens = load_json(args.tokens)
    output_path = args.output
    
    if not endpoints or not role_tokens:
        console.print("[red]Error: Invalid input files.[/red]")
        return

    if not validate_roles(role_tokens):
        console.print("[red]Error: Invalid role-token mapping.[/red]")
        return
    
    results = run_tests(endpoints, role_tokens)
    write_report(results, output_path)

if __name__ == "__main__":
    main()