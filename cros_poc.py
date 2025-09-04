#!/usr/bin/env python3
import requests

def check_cors(target):
    headers = {
        "Origin": "https://evil.com",
        "Referer": "https://evil.com",
        "User-Agent": "CORS-POC-Scanner/1.0"
    }

    try:
        print(f"[*] Testing CORS misconfiguration on: {target}\n")
        r = requests.get(target, headers=headers, timeout=10, verify=False)

        print(f"[+] HTTP {r.status_code}\n")
        print("--- Response Headers ---")
        for key, value in r.headers.items():
            if key.lower() in ["access-control-allow-origin", "access-control-allow-credentials", "location"]:
                print(f"{key}: {value}")

        if "access-control-allow-origin" in r.headers and "evil.com" in r.headers["access-control-allow-origin"]:
            if r.headers.get("access-control-allow-credentials", "").lower() == "true":
                print("\n[!!!] Vulnerable: Arbitrary Origin Reflection with Credentials Allowed")
            else:
                print("\n[!] Potential CORS misconfig: Origin reflected but credentials not allowed")
        else:
            print("\n[✓] No CORS misconfig detected.")

    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 cors_poc.py https://target.com")
        sys.exit(1)
    check_cors(sys.argv[1])
