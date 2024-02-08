import requests
import nmap
import json
from ipwhois import IPWhois

def print_red(text):
    print(f"\033[91m{text}\033[0m", end="")

def get_api_key(file_name):
    try:
        with open(file_name, 'r') as file:
            api_key = file.read().strip()
            return api_key
    except FileNotFoundError:
        print_red(f"{file_name} not found or inaccessible.")
        return None

def perform_scan(target):
    nm = nmap.PortScanner()
    nm.scan(target, arguments='-T4')

    for host in nm.all_hosts():
        print(f"Host: {host}")
        print(f"State: {nm[host].state()}")
        for proto in nm[host].all_protocols():
            print(f"Protocol: {proto}")
            ports = nm[host][proto].keys()
            sorted_ports = sorted(ports)
            for port in sorted_ports:
                state = nm[host][proto][port]['state']
                print(f"Port: {port}\tState: {state}")

def check_abuseipdb_reputation(ip, api_key):
    url = f'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'Key': api_key,
        'Accept': 'application/json'
    }
    params = {'ipAddress': ip}
    response = requests.get(url, headers=headers, params=params)

    if response.status_code == 200:
        result = response.json()
        print(f"AbuseIPDB results for IP {ip}:")
        for key, value in result['data'].items():
            print(f"{key}: {value}")
    else:
        print_red(f"Error: {response.status_code}, {response.text}")

    print("\033[91m=\033[0m" * 30)

def check_alienvault_reputation(ip, api_key):
    url = f'https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}'
    headers = {'X-OTX-API-KEY': api_key}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        result = response.json()
        with open(f"{ip}_alienvault_info.json", "w") as file:
            json.dump(result, file, indent=4)

        print(f"AlienVault OTX results for IP {ip} saved in {ip}_alienvault_info.json")

        print("Printing information from AlienVault result:")
        print(f"WHOIS Lookup: {result.get('whois', 'N/A')}")
        print(f"Reputation Score: {result.get('reputation', 'N/A')}")
        print(f"Indicator Type: {result.get('type_title', 'N/A')}")
        print(f"Indicator Value: {result.get('indicator', 'N/A')}")
        print(f"Pulse Count: {result['pulse_info'].get('count', 'N/A')}")

        print(f"ASN: {result.get('asn', 'N/A')}")

        print(f"City: {result.get('city', 'N/A')}")
        print(f"Region: {result.get('region', 'N/A')}")
        print(f"Continent Code: {result.get('continent_code', 'N/A')}")
        print(f"Country Code3: {result.get('country_code3', 'N/A')}")
        print(f"Country Code2: {result.get('country_code2', 'N/A')}")
        print(f"Subdivision: {result.get('subdivision', 'N/A')}")
        print(f"Latitude: {result.get('latitude', 'N/A')}")
        print(f"Longitude: {result.get('longitude', 'N/A')}")
        print(f"Accuracy Radius: {result.get('accuracy_radius', 'N/A')} meters")
        print(f"Country Code: {result.get('country_code', 'N/A')}")
        print(f"Country Name: {result.get('country_name', 'N/A')}")

        for section in result.get('sections', []):
            if section in result:
                print(f"{section.capitalize()} Information: {result[section]}")

    else:
        print_red(f"Error: {response.status_code}, {response.text}")

    print("\033[91m=\033[0m" * 30)
    print("\n")	

def check_ip_reputation(ip, api_key):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    headers = {'x-apikey': api_key}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        result = response.json()
        if 'data' in result:
            data = result['data']
            if 'attributes' in data and 'last_analysis_stats' in data['attributes']:
                analysis_stats = data['attributes']['last_analysis_stats']
                harmful = analysis_stats.get('malicious', 0) + analysis_stats.get('suspicious', 0)
                total = sum(analysis_stats.values())
                print_red(f"VirusTotal results for IP {ip}:\n")
                print(f"Malicious/Suspicious: {harmful}/{total}")
                if harmful > 0:
                    print_red("The IP is potentially unsafe.\n")
                else:
                    print("No engines detected this IP as malicious.")
            else:
                print_red("No analysis stats available for this IP.")
        else:
            print_red("No data available for this IP.")
    else:
        print_red(f"Error: {response.status_code}, {response.text}")

    try:
        obj = IPWhois(ip)
        results = obj.lookup_whois()

        print(f"WHOIS information for IP {ip}:")
        print(f"Country: {results['asn_country_code']}")
        print(f"ISP Name: {results['asn_description']}")

        if 'nets' in results and results['nets']:
            for net in results['nets']:
                if 'address' in net:
                    print(f"Address: {net['address']}")
                if 'phone' in net:
                    print(f"Phone Number: {net['phone']}")
                if 'emails' in net and isinstance(net['emails'], list):
                    print(f"Emails: {', '.join(net['emails'])}")
                elif 'emails' in net and isinstance(net['emails'], str):
                    print(f"Emails: {net['emails']}")
                else:
                    print("No email found")

    except Exception as e:
        print(f"WHOIS lookup failed for IP {ip}: {e}")

    print("\033[91m=\033[0m" * 30)

# Read IPs from a text file
file_path = 'ip_addresses.txt'
with open(file_path, 'r') as file:
    ip_addresses = file.read().splitlines()

# Fetch API key
vt_api_key = get_api_key('virustotal_api_key.txt')
abuse_ipdb_api_key = get_api_key('abuseipdb_api_key.txt')
alien_api_key = get_api_key('alien_api_key.txt')

if vt_api_key and abuse_ipdb_api_key and alien_api_key:
    for ip in ip_addresses:
        check_ip_reputation(ip, vt_api_key)
        check_abuseipdb_reputation(ip, abuse_ipdb_api_key)
        check_alienvault_reputation(ip, alien_api_key)
        # perform_scan(ip)
