#!/usr/bin/env python3
# CORS Misconfiguration Scanner
# Created by Hai - HackerOne Assistant

import argparse
import concurrent.futures
import csv
import requests
import sys
import urllib3
from urllib.parse import urlparse
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Constants
TEST_ORIGIN = "https://evil.com"
DEFAULT_TIMEOUT = 10
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
MAX_WORKERS = 10

def print_banner():
    banner = """
╔═══════════════════════════════════════════════════╗
║                                                   ║
║              CORS MISCONFIGURATION                ║
║                   SCANNER                         ║
║                                                   ║
╚═══════════════════════════════════════════════════╝
"""
    print(Fore.CYAN + banner)

def normalize_url(url):
    """Ensure URL has http:// or https:// prefix"""
    if not url.startswith(('http://', 'https://')):
        return f"https://{url}"
    return url

def check_cors_misconfiguration(url, timeout=DEFAULT_TIMEOUT):
    """Check if a URL has CORS misconfiguration"""
    try:
        normalized_url = normalize_url(url)
        headers = {
            "Origin": TEST_ORIGIN,
            "User-Agent": USER_AGENT
        }
        
        response = requests.get(
            normalized_url, 
            headers=headers, 
            timeout=timeout, 
            verify=False,
            allow_redirects=True
        )
        
        response_headers = {k.lower(): v for k, v in response.headers.items()}
        
        result = {
            "url": normalized_url,
            "status_code": response.status_code,
            "vulnerable": False,
            "acao": None,
            "acac": None,
            "vary": None,
            "error": None
        }
        
        if "access-control-allow-origin" in response_headers:
            result["acao"] = response_headers["access-control-allow-origin"]
            result["acac"] = response_headers.get("access-control-allow-credentials", None)
            if result["acac"]:
                result["acac"] = result["acac"].lower()
            
            result["vary"] = response_headers.get("vary", None)
            
            # Logic for vulnerability determination:
            # 1) If allow-credentials is true, allow-origin must not be "*"
            #    and must reflect the test origin to be vulnerable
            # 2) If allow-credentials is false or missing, allow-origin of "*" or test origin indicates possible misconfig
            if result["acac"] == "true":
                if result["acao"] == TEST_ORIGIN:
                    result["vulnerable"] = True
            else:
                if result["acao"] == TEST_ORIGIN or result["acao"] == "*":
                    result["vulnerable"] = True
        
        return result

    except requests.exceptions.RequestException as e:
        return {
            "url": url,
            "status_code": None,
            "vulnerable": False,
            "error": str(e),
            "acao": None,
            "acac": None,
            "vary": None
        }

def process_url(url, timeout=DEFAULT_TIMEOUT):
    """Process a single URL and print results"""
    result = check_cors_misconfiguration(url, timeout)
    
    if result["status_code"] is None:
        print(f"{Fore.YELLOW}[!] Error checking {url}: {result.get('error', 'Unknown error')}")
        return result
    
    if result["vulnerable"]:
        print(f"{Fore.RED}[VULNERABLE] {url} - CORS Misconfiguration Detected!")
        print(f"  - Status Code: {result['status_code']}")
        print(f"  - Access-Control-Allow-Origin: {result['acao']}")
        print(f"  - Access-Control-Allow-Credentials: {result['acac']}")
        if result["vary"]:
            print(f"  - Vary: {result['vary']}")
    else:
        print(f"{Fore.GREEN}[SECURE] {url} - No CORS Misconfiguration")
    
    return result

def save_to_csv(results, output_file):
    """Save results to CSV file"""
    with open(output_file, 'w', newline='') as csvfile:
        fieldnames = ['url', 'status_code', 'vulnerable', 'acao', 'acac', 'vary', 'error']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for result in results:
            # Ensure all keys exist in dict for CSV writing
            row = {field: result.get(field, '') for field in fieldnames}
            writer.writerow(row)
    
    print(f"
{Fore.CYAN}Results saved to {output_file}")

def main():
    parser = argparse.ArgumentParser(description='CORS Misconfiguration Scanner')
    parser.add_argument('-f', '--file', help='File containing list of URLs/domains')
    parser.add_argument('-u', '--url', help='Single URL to test')
    parser.add_argument('-o', '--output', help='Output CSV file', default='cors_results.csv')
    parser.add_argument('-t', '--threads', type=int, default=MAX_WORKERS, help='Number of threads')
    parser.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT, help='Timeout for HTTP requests (seconds)')
    
    args = parser.parse_args()
    
    print_banner()
    
    urls = []
    
    if args.url:
        urls = [args.url]
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{Fore.RED}Error: File {args.file} not found")
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)
    
    print(f"{Fore.CYAN}Starting CORS Misconfiguration Scan on {len(urls)} URLs...")
    print(f"Using {args.threads} threads, Timeout: {args.timeout}s
")
    
    results = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_url = {executor.submit(process_url, url, args.timeout): url for url in urls}
        
        for future in concurrent.futures.as_completed(future_to_url):
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as exc:
                url = future_to_url[future]
                print(f"{Fore.YELLOW}[!] Error occurred while scanning {url}: {exc}")
    
    vulnerable_count = sum(1 for r in results if r["vulnerable"])
    error_count = sum(1 for r in results if r["status_code"] is None)
    
    print(f"
{Fore.CYAN}=== Scan Summary ===")
    print(f"Total URLs scanned: {len(results)}")
    print(f"{Fore.RED}Vulnerable endpoints: {vulnerable_count}")
    print(f"{Fore.YELLOW}Errors/Timeouts: {error_count}")
    print(f"{Fore.GREEN}Secure endpoints: {len(results) - vulnerable_count - error_count}")
    
    if results:
        save_to_csv(results, args.output)

if __name__ == "__main__":
    main()