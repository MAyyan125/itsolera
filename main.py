import argparse
import whois
import requests
import nmap
import subprocess
import json
import dns.resolver
from urllib.parse import urlparse
import datetime

print(datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S]"))


# argparse
parser = argparse.ArgumentParser(description='Help description')
parser.add_argument('-w', '--whois_lookup', help='Print whois lookup')
parser.add_argument('-d', '--dns', help='DNS Enumiration')
parser.add_argument('-s', '--sub', help='Subdomain Enumiration')
parser.add_argument('-p', '--port', help='Port scanning using nmap')
parser.add_argument('-b', '--banner', help='Banner Grabbing using nmap')
parser.add_argument('-t', '--techdetect', help='Detecting technologies')
args = parser.parse_args()

# WHOIS
if args.whois_lookup:
    def whois_lookup(domain):
        try:
            w = whois.whois(domain)
            print(f"WHOIS Lookup for {domain}:\n{w}")
        except Exception as e:
            print(f"Error: {e}")
    whois_lookup(args.whois_lookup)

# DNS Enumeration
if args.dns:
    def clean_domain(domain):
        parsed = urlparse(domain)
        hostname = parsed.netloc if parsed.netloc else parsed.path
        root_domain = hostname.replace("www.", "")
        return hostname, root_domain

    def run_dns_enum(domain_input):
        subdomain, root_domain = clean_domain(domain_input)
        print(f"=== DNS ENUMERATION for {subdomain} ===")

        record_types = {
            'A': subdomain,
            'MX': root_domain,
            'TXT': root_domain,
            'NS': root_domain
        }

        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '1.1.1.1']

        for rtype, target_domain in record_types.items():
            print(f"[{rtype} Records for {target_domain}]")
            try:
                answers = resolver.resolve(target_domain, rtype, lifetime=5)
                for rdata in answers:
                    print(f"  - {rdata}")
            except Exception as e:
                print(f"  [!] Error: {rtype} - {e}")
    run_dns_enum(args.dns)

# Subdomain Enumeration
if args.sub:
    def subdomain_enum(domain):
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            resp = requests.get(url, timeout=10)
            subdomain = resp.json()
            subdomains = set()
            for sub in subdomain:
                subdomains.add(sub["common_name"])
            for x in subdomains:
                print(f"{x}")
        except Exception as e:
            print(f"Error: {e}")
    global temp
    temp=list
    subdomain_enum(args.sub)

# Banner Grabbing
if args.banner:
    def banner_grab(target_ip, ports="1-1024"):
        nm = nmap.PortScanner()
        nm.scan(target_ip, ports, arguments='-sV')
        for host in nm.all_hosts():
            print(f"Host: {host}")
            for proto in nm[host].all_protocols():
                print(f"Protocol: {proto}")
                lport = nm[host][proto].keys()
                for port in sorted(lport):
                    state = nm[host][proto][port]['state']
                    name = nm[host][proto][port]['name']
                    print(f"Port: {port}\tState: {state}\tService: {name}")
    banner_grab(args.banner)

# Port Scanning
if args.port:
    def portscan(target_ip):
        scan = nmap.PortScanner()
        scan.scan(target_ip, arguments="-F")
        for host in scan.all_hosts():
            print(f"Host: {host}")
            for proto in scan[host].all_protocols():
                print(f"Protocol: {proto}")
                lport = scan[host][proto].keys()
                for port in sorted(lport):
                    state = scan[host][proto][port]['state']
                    name = scan[host][proto][port]['name']
                    print(f"Port: {port}\tState: {state}\tService: {name}")
    portscan(args.port)


# Detecting Technologies
if args.techdetect:
  def detect_with_whatweb(url):
    try:
        print(f"[*] Scanning {url} with WhatWeb...\n")
        result = subprocess.run(['whatweb', url], capture_output=True, text=True)
        if result.returncode == 0:
            print(result.stdout)
        else:
            print(f"[!] Error: {result.stderr}")
    except FileNotFoundError:
        print("[!] WhatWeb is not installed. Please install it using: sudo apt install whatweb")
  detect_with_whatweb(args.techdetect)
