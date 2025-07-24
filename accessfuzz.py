#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import time
import requests
from typing import Dict

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

# === Input Configuration ===
endpoints = [
    {
        "method": "GET",
        "url": "http://localhost:5000/api/admin/dashboard",
        "headers": {},
        "params": {},
        "data": None
    },
    {
        "method": "GET",
        "url": "http://localhost:5000/api/user/profile/1",
        "headers": {},
        "params": {},
        "data": None
    },
    {
        "method": "GET",
        "url": "http://localhost:5000/api/user/profile/2",
        "headers": {},
        "params": {},
        "data": None
    },
    {
        "method": "GET",
        "url": "http://localhost:5000/api/user/profile/3",
        "headers": {},
        "params": {},
        "data": None
    }
]

# === Roles & Tokens ===

role_tokens = {
    "admin": {"Authorization": "Bearer ADMIN_TOKEN"},
    "user": {"Authorization": "Bearer USER_TOKEN"},
    "guest": {"Authorization": "Bearer GUEST_TOKEN"},
}

def test_endpoint(endpoint, role, token_headers):
    method = endpoint["method"]
    url = endpoint["url"]
    headers = {**endpoint["headers"], **token_headers}
    params = endpoint.get("params", {})
    data = endpoint.get("data", None)

    try:
        resp = requests.request(method, url, headers=headers, params=params, json=data, timeout=5)
        return resp.status_code, resp.text
    except Exception as e:
        return 0, str(e)

def run_tests():
    results = []

    for ep in endpoints:
        print(f"\n[+] Testing endpoint: {ep['method']} {ep['url']}")
        for role, headers in role_tokens.items():
            status_code, response = test_endpoint(ep, role, headers)
            print(f"    [{role.upper()}] → Status: {status_code}")
            results.append({
                "endpoint": ep["url"],
                "method": ep["method"],
                "role": role,
                "status": status_code
            })
            time.sleep(0.5)

    return results

if __name__ == "__main__":
    print_banner()
    results = run_tests()

    with open("accessfuzz_report.json", "w") as f:
        json.dump(results, f, indent=2)

    print("\n[+] Scan complete. Report saved to accessfuzz_report.json")
