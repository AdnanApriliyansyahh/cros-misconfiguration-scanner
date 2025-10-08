# CORS Misconfiguration PoC Scanner
A simple Python script to test for potential CORS (Cross-Origin Resource Sharing) misconfigurations in web applications.
The purpose of this tool is to help security researchers and penetration testers validate whether a domain or web API improperly allows access from arbitrary origins (evil.com), which could lead to sensitive data exposure.

### Features

• Sends HTTP requests with spoofed Origin and Referer headers (https://evil.com).

• Displays key response headers related to CORS:

• Access-Control-Allow-Origin

• Access-Control-Allow-Credentials

• Location (in case of redirects)

Provides simple analysis:

• No CORS misconfiguration detected.

• Potential misconfiguration (Origin reflected without credentials).

• Vulnerable (Arbitrary Origin reflection with credentials allowed).

### Usage

```
git clone https://github.com/AdnanApriliyansyahh/cros-misconfiguration-scanner
```
```
cros-misconfiguration-scanner
```
```
pip install requests colorama urllib3
```
```
chmod +x cors_scanner.python
```
**Singel Domain**
```
python3 main.py -u https://target.com -o output.txt
```
**Multiple Domain**
```
python3 main.py -f subdomain.txt -o output.txt
```
**To set the number of threads**
```
python3 main.py -f subdomains.txt -t 20
```