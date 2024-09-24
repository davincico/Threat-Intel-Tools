import requests
import json
from bs4 import BeautifulSoup
from prettytable import PrettyTable 
# import urllib3
# urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# pip install prettytable
# Guide: https://pypi.org/project/prettytable/

# REFERENCE: https://github.com/stanfrbd/check_ip/tree/main

"""
Spur.us & ipinfo for IP enrichment
Spur.us requires API key for better access
"""

def get_ipinfo(ip):
    ipinfo_url = f"https://ipinfo.io/{ip}"
    ipinfo_data = requests.get(ipinfo_url, verify=True)
    return ipinfo_data

def get_spur(ip):
    spur_url = f"https://spur.us/context/{ip}"
    spur_data = requests.get(spur_url, verify=True)
    #print(spur_data.text)

    # page.text = content of response, parses it from python's in built html.parser 
    soup = BeautifulSoup(spur_data.text, 'html.parser')
    title_tag = soup.title

    # generate list of spur information components
    type_use = soup.find_all(class_="font-weight-normal")
    list = []
    for i in type_use:
        list.append(i.text)
    x = (''.join(list))
    #print(x)
    """
    Guide to filtering out wanted data from scraped raw contents:
    https://www.digitalocean.com/community/tutorials/how-to-scrape-web-pages-with-beautiful-soup-and-python-3
              <i class="fas fa-ethernet fa-1x mr-3"></i>

          142.251.40.174
          -
          Not Anonymous
                  </h2>
        <p class="font-weight-normal monospace py-3">
          142.251.40.174 itself does not appear to be part of anonymization infrastructure.
          We have seen limited device activity on 142.251.40.174.
                            </p>
                  <span class="d-inline-block">Few Devices Online</span>
            </h4>
            <p class="font-weight-normal">
              This IP address (142.251.40.174) is not being used by many devices.
              The low device count for 142.251.40.174 indicates that it may be privately
              allocated to specific customers.
              Datacenter IPs like 142.251.40.174 can be used in fake user or bot activity which is not accounted for in
              this
              metric.
              IP Addresses that have fewer unique users are generally less effective at anonymizing activity online.
            </p>
          </div>
          <div class="col-12 m-3">
            <h4 class="h2 font-weight-normal mb-3 ">
              <i class="fas fa-server mr-3"></i>
              <span class="d-inline-block">DATACENTER</span>
            </h4>
            <p class="font-weight-normal">
              This IP is owned by Google LLC and is hosted in
              US.
              This IP belongs to DATACENTER infrastructure.
              Datacenter IPs like 142.251.40.174 typically route user traffic when they are acting as a VPN, Proxy, Cloud
              Gateway or are performing some automated activity.
            </p>
          </div>
    """


    if title_tag is not None:
        title_text = title_tag.get_text()
            
        if "(" in title_text and ")" in title_text:
            content = title_text.split("(")[1].split(")")[0].strip()
        else:
            content = "Not Anonymous"
    print("[+] Returning data from Spur.us:")
    print(x)
    return content

def process_ip(ip):
    ipinfo_data = get_ipinfo(ip)
    ipinfo_json = json.loads(ipinfo_data.text)

    data = {
        "IP": ip,
        "City": ipinfo_json['city'],
        "Region": ipinfo_json['region'],
        "Country": ipinfo_json['country'],
        "Location": ipinfo_json['loc'],
        "ISP": ipinfo_json['org'],
        "Postal": ipinfo_json['postal'] if 'postal' in ipinfo_json else "Unknown",
        "Timezone": ipinfo_json['timezone'],
        "VPN Vendor (Spur)": get_spur(ip)
    }

    table = PrettyTable()
    table.field_names = ["Key", "Value"]

    for key, value in data.items():
        table.add_row([key, value])

    print(table)
    print("\n")

    return data

# Function requires jwt_token
def process_ip_with_spur(ip):
    
    ip_address = ip
    jwt_token = 'read_token() or get_token()'

    headers = {
        "Host": "app.spur.us",
        "Sec-Ch-Ua": "\"Not(A:Brand\";v=\"24\", \"Chromium\";v=\"122\"",
        "Sec-Ch-Ua-Mobile": "?0",
        "Authorization": f"Bearer {jwt_token}",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.112 Safari/537.36",
        "Sec-Ch-Ua-Platform": "\"Linux\"",
        "Accept": "*/*",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Referer": f"https://app.spur.us/context?q={ip_address}",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-US,en;q=0.9",
        "Priority": "u=1, i"
    }

    # Original request URL
    # url = f"https://app.spur.us/api/v1/search/{ip_address}"

    # Using SPUR Context API 
    url = f"https://api.spur.us/v2/context/{ip_address}"

    response = requests.get(url, headers=headers, verify=False)

    if response.status_code == 200:
        data = response.json().get('data', {})
        v2 = data.get('v2', {})
        location = v2.get('location', {})
        client = v2.get('client', {})

        return {
            "ip": v2.get("ip", ""),
            "organization": v2.get("organization", ""),
            "city": location.get("city", ""),
            "country": location.get("country", ""),
            "state": location.get("state", ""),
            "infrastructure": v2.get("infrastructure", ""),
            "risks": ", ".join(v2.get("risks", [])),
            "client_types": ", ".join(client.get("types", [])),
            "client_behaviors": ", ".join(client.get("behaviors", [])),
            "client_proxies": ", ".join(client.get("proxies", [])),
            "tunnels": ", ".join([tunnel.get("operator", "") for tunnel in v2.get("tunnels", [])])
        }
    else:
        print(f"Failed to process IP {ip_address}. Status code: {response.status_code}")
        return None

