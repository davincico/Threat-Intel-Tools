import requests
import time
from tqdm import tqdm

# API key needed
# Query own API key current limit using this: 
# https://urlscan.io/docs/api/

"""
Ref:
https://github.com/ThatSINEWAVE/URL-Analysis-Tool/blob/main/urlscan_module.py
"""

def submit_to_urlscan(url, api_key):
    headers = {'API-Key': api_key, 'Content-Type': 'application/json'}
    data = {"url": url, "visibility": "public"}
    response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, json=data)
    if response.status_code == 200:
        # The response to the API call will return the following JSON object, including the unique scan UUID and API endpoint for the scan. With the unique UUID you can retrieve the scan result, screenshot and DOM snapshot after waiting for a while. While the scan is still in progress, the Result API endpoint will respond with the 404 code.
        # The suggested polling logic would be to wait 10-30 seconds directly after submission and then polling in 5-second intervals until the scan is finished or a maximum wait time has been reached.
        # {
        #   "message": "Submission successful",
        #   "uuid": "0e37e828-a9d9-45c0-ac50-1ca579b86c72",
        #   "result": "https://urlscan.io/result/0e37e828-a9d9-45c0-ac50-1ca579b86c72/",
        #   "api": "https://urlscan.io/api/v1/result/0e37e828-a9d9-45c0-ac50-1ca579b86c72/",
        #   "visibility": "public",
        #   "options": {
        #     "useragent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.61 Safari/537.36"
        #   },
        #   "url": "https://urlscan.io",
        #   "country": "de"
        # }
        """
        Solution is to split into submission & report retrieval functions
        """

        scan_uuid = response.json().get('uuid')
        return scan_uuid
    else:
        print(f"[URLSCAN] RESPONSE={response.status_code}")
        return None

# Default delay is 15s for the scan results, then use scan ID from submission API to poll for scan
def get_urlscan_result(scan_uuid, api_key, retries=4, delay=15):
    result_url = f'https://urlscan.io/api/v1/result/{scan_uuid}/'
    headers = {'API-Key': api_key}

    for attempt in range(retries):
        time.sleep(delay)  # Wait before checking if the scan is ready
        response = requests.get(result_url, headers=headers)
        if response.status_code == 200:
            scan_data = response.json()
            return scan_data
        else:
            print(f"[URLSCAN] ATTEMPT={attempt + 1}/{retries}, Reasons: 404-scan still ongoing, 410-scan result has been deleted, Please check status code:\n[*] Status Code={response.status_code}")

    return None

# // COLORS
RED = "\033[91m"
YELLOW = "\033[93m"
LIGHT_GREEN = "\033[92;1m"
LIGHT_BLUE = "\033[96m"
RESET = "\033[0m"

# // Loading bar
def loading_bar(interval):
    """
    Simple tqdm display-only loading bar with specified jump intervals
    """
    for i in tqdm(range(10)):
        time.sleep(interval) #how fast to load the bar, jumps in x seconds

def urlscan_submit_retrieve(url, api_key):
    scan_uuid = submit_to_urlscan(url, api_key)
    if scan_uuid:
        print("Scan submitted successfully.")
        print("Waiting for scan results from urlscan, please allow 10-25s...")
        loading_bar(1) # 10s minimum for urlscan
        scan_data = get_urlscan_result(scan_uuid, api_key)
        if scan_data:
            result_url = f'https://urlscan.io/result/{scan_uuid}/'
            
            print(f"Scanned URL: {url}\n{LIGHT_GREEN}[*] Urlscan Results: {result_url}")
            print(f"[*] You can obtain the target URL screenshot here:\nhttps://urlscan.io/screenshots/{scan_uuid}.png{RESET}")
            print(f"[*] You can obtain the target DOM snapshot here:\n https://urlscan.io/dom/{scan_uuid}/")
            # return scan_data
        else:
            return "[!] Failed to retrieve scan results."
    else:
        return "[!] Failed to submit the URL for scanning."
