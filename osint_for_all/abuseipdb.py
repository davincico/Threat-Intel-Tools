import requests
from rich.console import Console
from rich.table import Table
from rich import print
from dotenv import load_dotenv
import os

load_dotenv()
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY', 'YourAPIKeyifnotSet')
#abuseipdb API Key - 1000/day checks


def check_abuseipdb(ip, details): # details is boolean flag
    # How far back to fetch the report (default is 90 days)
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36" 
    } 
    # https://www.zenrows.com/blog/user-agent-web-scraping#what-is
    response = requests.get(url, headers=headers)
    default_confidence_score = 0

    if response.status_code == 200:
        data = response.json()
        #print(data) # preview the raw data
        """
                {
            'data': {
                'ipAddress': '142.251.40.174',
                'isPublic': True,
                'ipVersion': 4,
                'isWhitelisted': False,
                'abuseConfidenceScore': 0,
                'countryCode': 'US',
                'usageType': 'Data Center/Web Hosting/Transit',
                'isp': 'Google LLC',
                'domain': 'google.com',
                'hostnames': ['lga25s81-in-f14.1e100.net'],
                'isTor': False,
                'totalReports': 0,
                'numDistinctUsers': 0,
                'lastReportedAt': '2023-10-25T17:02:04+00:00'
            }
        }
        """
        r_Score = str(data['data']['abuseConfidenceScore'])
        r_Domain = data['data']['domain']
        r_Reports_Count = str(data['data']['totalReports'])
        r_Country_Code = data['data']['countryCode']
        r_Latest_Report = data['data']['lastReportedAt']
        r_Isp = str(data['data']['isp'])
        r_UsageType = str(data['data']['usageType'])
        # Python will recognise raw hostname as a list, make sure to strip square brackets
        r_Hostnames = str(data['data']['hostnames']).replace("[","").replace("'","").replace("]","")
        
        console = Console()
        table = Table(title="Table Summary from AbuseIPDB", caption=f"Default confidence score:  [yellow]{default_confidence_score}[yellow]")
        table.add_column("IP Address", justify="left")
        table.add_column("Score", justify="center")
        table.add_column("Domain", justify="left")
        table.add_column("ISP", justify="center")
        table.add_column("Usage Type", justify="center")
        table.add_column("Hostnames", justify="center")
        table.add_column("Reports", justify="center")
        table.add_column("Country", justify="center")
        table.add_column("Last Scanned at", justify="left")
        
        settings_confidenceScore = 50 # Preset Threshold
        
        
        if details: # print details of IP check (Score, Domain, Reports, Country, Latest Report)
            if int(r_Score) >= settings_confidenceScore and int(r_Score) >= 1:
                
                table.add_row(ip, r_Score, r_Domain, r_Isp, r_UsageType, r_Hostnames, r_Reports_Count, r_Country_Code, r_Latest_Report)
                console.print(table)
                print("")
            else:
                
                table.add_row(ip, r_Score, r_Domain, r_Isp, r_UsageType, r_Hostnames, r_Reports_Count, r_Country_Code, r_Latest_Report)
                table.caption = f"IP address [bold green]{ip}[/bold green] has not been reported as malicious!\n"
                console.print(table)
                print("")
        else:
            if int(r_Score) >= settings_confidenceScore:
                print(f"\nIP address [bold red]{ip}[/bold red] assigned to domain [bold red]{r_Domain}[/bold red] has been reported as malicious with a confidence score of [[bold red]{data['data']['abuseConfidenceScore']}[/bold red]].\n")
            else:
                print(f"\nIP address [bold green]{ip}[/bold green] assigned to domain [bold green]{r_Domain}[/bold green] has NOT been reported as malicious with a confidence score of [[bold green]{data['data']['abuseConfidenceScore']}[/bold green]].\n")    

    else:
        errors = response.json().get('errors', [])
        error_detail = errors[0].get('detail', 'Unknown error')
        output_results = f'\n[!] Error checking IP {ip}: {error_detail}\n'
        print(f'\n[!] Error checking IP Address [bold yellow]{ip}[/bold yellow]: [red]{error_detail}[/red]\n')
        return output_results
    
# FUNCTION CALL
# check_abuseipdb('142.251.40.174', True)

"""
Details = True
                                  List of Checked IP
┏━━━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ IP Address     ┃ Score ┃ Domain     ┃ Reports ┃ Country ┃ Lastest Report            ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 142.251.40.174 │   0   │ google.com │    0    │   US    │ 2023-10-25T17:02:04+00:00 │
└────────────────┴───────┴────────────┴─────────┴─────────┴───────────────────────────┘
             IP address 142.251.40.174 has not been reported as malicious!

Details = False
IP address 142.251.40.174 assigned to domain google.com has not been reported as malicious with a confidence score of [0].
"""