import requests
import argparse
# from tabulate import tabulate
import ipaddress
import json
from urlscan import *
from spur_ip import *
from abuseipdb import check_abuseipdb
import os
from dotenv import load_dotenv

load_dotenv()

urlscan_api_key = os.getenv('urlscan_api_key', 'YourAPIKeyifnotSet') # 150k public scans per day
VT_API_KEY = os.getenv('VT_API_KEY', 'YourAPIKeyifnotSet')
# Replace with your VirusTotal API key
# 4 lookups per min, 500 per day (15.5k per month)

"""
Current integrations include:
1. VirusTotal 
2. Urlscan.io
3. siterview (to overcome script/scrapper blockers) 
3. whois (to fix, servers perpetually time out)
4. IPinfo
5. Spur.us
"""
# SAMPLE IP for testing: 142.251.40.174 google.com
# pip install python-whois, prettytable
# Guide: https://pypi.org/project/prettytable/
  

# // COLORS
RED = "\033[91m"
YELLOW = "\033[93m"
LIGHT_GREEN = "\033[92;1m"
LIGHT_BLUE = "\033[96m"
RESET = "\033[0m"

# // VirusTotal Module V2
def get_report(resource):
    url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': VT_API_KEY, 'resource': resource}
    response = requests.get(url, params=params)
    return response.json()

def scan_url(resource):
    url = 'https://www.virustotal.com/vtapi/v2/url/scan'
    params = {'apikey': VT_API_KEY, 'url': resource}
    response = requests.post(url, data=params)
    return response.json()

def scan_ip(resource):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{resource}'

    headers = {
        'Accept': 'application/json',
        'x-apikey': VT_API_KEY
    }

    response = requests.request(method='GET', url=url, headers=headers)
    decodedResponse = json.loads(response.text)
    return decodedResponse   

# Parse output from VT for IP analysis
def filter_data(data): 
    # Add: network, last_analysis_stats (malicious, suspicious),
    if 'error' in data:
        details = f"Details: {data['error']['message']}"
        output = f"\n[-] VirusTotal\n{details}\n"
    elif 'private' in data['data']['attributes']['tags']:
        ip_address = data['data']['id']
        output = f"\n[-] VirusTotal\nIP Address {ip_address} is not a public IP Address\n"
    else:
        if 'network' in data['data']['attributes']:
            network = f"Network: {data['data']['attributes']['network']}"
        else:
            network = "Network: N/A"
        harmless_report = f" - Harmless: {data['data']['attributes']['last_analysis_stats']['harmless']}"
        malicious_report = f" - Malicious: {data['data']['attributes']['last_analysis_stats']['malicious']}"
        suspicious_report = f" - Suspicious: {data['data']['attributes']['last_analysis_stats']['suspicious']}"
        country = f"Country: {data['data']['attributes']['country']}"
        AS_no = f"AS Number: {data['data']['attributes']['whois']}"

        link = f"{LIGHT_GREEN}[*] VirusTotal results link:{RESET}\n{data['data']['links']['self']}"
        output = f"\n[*] VirusTotal\n{LIGHT_GREEN}Security Vendors' Analysis{RESET}\n{harmless_report}\n{malicious_report}\n{suspicious_report}\n{network}\n\n{LIGHT_GREEN}[*] Geolocation & Other information{RESET}\n{country}\n{AS_no}\n{link}"

    return output

# Optional function to table out Scanner:Detected:Result 
# def format_report(report):
#     if 'scans' in report:
#         table_data = []
#         for scanner, result in report['scans'].items():
#             table_data.append([scanner, result['detected'], result['result']])
#         return tabulate(table_data, headers=['Scanner', 'Detected', 'Result'], tablefmt='grid')
#     else:
#         return '[!] No scan data available.'

# select certain keys in the json output to output
def print_selected_keys(json_obj, keys):
    """
    Prints the specified keys and their values from a JSON object.
    
    :param json_obj: The JSON object (dictionary) to print keys from.
    :param keys: A list of keys to extract and print.
    """
    total = json_obj['total']

    for key in keys:
        if key in json_obj:
            if key == 'positives':
                print(f'Number of hits on VT: {json_obj[key]}/{total}')
            elif key == 'total':
                pass
            else:
                print(f'{key}: {json_obj[key]}')
           
# Define keys we need from VT output 
keys_to_extract = ['permalink', 'positives', 'resource', 'scan_date', 'scan_id', 'total', 'url']


# checks if input is ip address
def is_ip_address(input_str):
    """
    Checks if the input string is a valid IP address.
    
    :param input_str: The input string to check.
    :return: True if the input is a valid IP address, False otherwise.
    """
    try:
        ipaddress.ip_address(input_str)
        return True
    except ValueError:
        return False
    


def main():
    """
    Takes 1 input: IP address, URL or Domain for enrichment and analysis
    Full suite of Tools
    1. IP address enrichment
        - VirusTotal
        - AbuseIPDB
        - IPinfo
        - Spur.us (pending)
    2. URLs & Domains
        - VirusTotal
        - Urlscan.io
        - SiteReview (pending)
        
    """
    parser = argparse.ArgumentParser(description='Scan an IP address, URL, or domain using OSINT Suite.')
    parser.add_argument('resource', help='The IP address, URL, or domain to scan.')
    args = parser.parse_args()

    resource = args.resource

    if is_ip_address(resource):
        """
        Perform IP Address OSINT Exposure checks using: VT, AbuseIPDB, IPinfo, Spur.us
        """
        print(f'{LIGHT_GREEN}[*] Submitting the IP address indicator on VirusTotal: {resource}{RESET}')
    
        scan_result = scan_ip(resource)
        #print(scan_result) # submission URL
        
        print('[*] Scan request successfully submitted.')
        report = filter_data(scan_result)
        print(f'\n{YELLOW}=============================== VirusTotal ==============================={RESET}')                
        print(report)
        print(f'{LIGHT_GREEN}[*] Submitting the indicator on AbuseIPDB: {resource}{RESET}')
        print(f'\n{YELLOW}=============================== AbuseIPDB ==============================={RESET}')
        check_abuseipdb(resource, True) #Default set to full details
        print(f'{LIGHT_GREEN}[*] Submitting the indicator on Spur & Ipinfo: {resource}{RESET}')
        print(f'\n{YELLOW}=============================== IP Enrichment on Spur & Ipinfo ==============================={RESET}')        
        process_ip(resource)
        

    else: # Non-IP address: URL, domain, File Hash
        """
        Perform URL/Domain exposure checks using: VT, Sitereview, URLscan
        """
        print(f'{LIGHT_GREEN}[*] Submitting the indicator on VirusTotal: {resource}{RESET}')
    
        scan_result = scan_url(resource)
        #print(scan_result) # submission URL
        if scan_result['response_code'] == 1:
            print('[*] Scan request successfully submitted.')
            report = get_report(resource)
            #print(report) # response
            
            if report['response_code'] == 1:
                print(f'\n{YELLOW}=============================== VirusTotal ==============================={RESET}')
                # Select certain keys and print
                print_selected_keys(report, keys_to_extract)
            else:
                print('[!] Error fetching report:', report['verbose_msg'])
        else:
            print('[!] Error submitting scan request:', scan_result['verbose_msg'])


        print(f'\n{LIGHT_GREEN}[*] Submitting the indicator on Urlscan: {resource}{RESET}')
        print(f'\n{YELLOW}=============================== Urlscan ==============================={RESET}')
        urlscan_submit_retrieve(resource, urlscan_api_key)
        


if __name__ == '__main__':
    main()
