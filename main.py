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
TIMEOUT = 10
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
MAX_WORKERS = 10

def print_banner():
    banner = """
    ╔═══════════════════════════════════════════════════╗
    ║                                                   ║
    ║              CORS MISCONFIGURATION                ║
    ║                   SCANNER                         ║
    ║                                                   ║
    ║                         
    ║                                                   ║
    ╚═══════════════════════════════════════════════════╝
    """
    print(Fore.CYAN + banner)

def normalize_url(url):
    """Ensure URL has http:// or https:// prefix"""
    if not url.startswith(('http://', 'https://')):
        return f"https://{url}"
    return url

def check_cors_misconfiguration(url):
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
            timeout=TIMEOUT, 
            verify=False,
            allow_redirects=True
        )
        
        # Extract headers for analysis (case-insensitive)
        response_headers = {k.lower(): v for k, v in response.headers.items()}
        
        result = {
            "url": normalized_url,
            "status_code": response.status_code,
            "vulnerable": False,
            "acao": None,
            "acac": None,
            "vary": None
        }
        
        # Check for Access-Control-Allow-Origin header
        if "access-control-allow-origin" in response_headers:
            result["acao"] = response_headers["access-control-allow-origin"]
            
            # Check for Access-Control-Allow-Credentials
            if "access-control-allow-credentials" in response_headers:
                result["acac"] = response_headers["access-control-allow-credentials"]
            
            # Check for Vary header
            if "vary" in response_headers:
                result["vary"] = response_headers["vary"]
            
            # Check if origin is reflected and credentials allowed
            if (result["acao"] == TEST_ORIGIN or result["acao"] == "*") and \
               result["acac"] == "true":
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

def process_url(url):
    """Process a single URL and print results"""
    result = check_cors_misconfiguration(url)
    
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
            writer.writerow(result)
    
    print(f"\n{Fore.CYAN}Results saved to {output_file}")

def main():
    parser = argparse.ArgumentParser(description='CORS Misconfiguration Scanner')
    parser.add_argument('-f', '--file', help='File containing list of URLs/domains')
    parser.add_argument('-u', '--url', help='Single URL to test')
    parser.add_argument('-o', '--output', help='Output CSV file', default='cors_results.csv')
    parser.add_argument('-t', '--threads', type=int, default=MAX_WORKERS, help='Number of threads')
    
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
    print(f"Using {args.threads} threads\n")
    
    results = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_url = {executor.submit(process_url, url): url for url in urls}
        
        for future in concurrent.futures.as_completed(future_to_url):
            result = future.result()
            if result:
                results.append(result)
    
    # Summary
    vulnerable_count = sum(1 for r in results if r["vulnerable"])
    error_count = sum(1 for r in results if r["status_code"] is None)
    
    print(f"\n{Fore.CYAN}=== Scan Summary ===")
    print(f"Total URLs scanned: {len(results)}")
    print(f"{Fore.RED}Vulnerable endpoints: {vulnerable_count}")
    print(f"{Fore.YELLOW}Errors/Timeouts: {error_count}")
    print(f"{Fore.GREEN}Secure endpoints: {len(results) - vulnerable_count - error_count}")
    
    if results:
        save_to_csv(results, args.output)

if __name__ == "__main__":
    main()