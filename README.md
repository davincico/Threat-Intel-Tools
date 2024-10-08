# All-in-One OSINT IP & URL & Domain Indicator Enrichment Tool
## Apollo.py 
**An all in one tool for IP/URL/Domain analysis and enrichment.**

![alt text](/img/badges.png)

**There are 2 options for this tool: plaintext output and Tabled output**. They are stored in *osint_for_all* and *osint_for_all_TABLE* folders respectively.

Tired of running the same URL/IP or domain indicator across different analysis platforms and tools manually? This tool allows you to run the same target across a multitude of analysis and reputation check platforms, allowing a seamless experience and a combined output with just one click.

**Tools in the suite:**
At the current stage, tool only uses API keys for VT, AbuseIPDB and Urlscan.
1. VirusTotal - Scans IP address/URL/Domain for reputation checks
2. AbuseIPDB - IP enrichment
3. Urlscan.io - generates the URL site screenshots and dom snapshot links 
4. IPinfo - IP enrichment
5. Spur.us - IP enrichment
6. SiteReview - URL/Domain categorization checks (pending development)

## Usage
**Target:** Single IP address, URL or domain to investigate
Use Python3!

A simple single command to run the tool `python3 apollo.py <target>`
Tool will automatically parse the input and determine the type of indicator it is, executing the appropriate modules relavant to the indicator type.

## Setting up
1. Install the relevant dependencies:
`pip install python-dotenv rich prettytable beautifulsoup4 tqdm`

2. Fill in the sample_env.txt with your API Keys and rename file to `.env`. Make sure it remains in the same folder as Apollo.py.

You will need VirusTotal, Urlscan and Abuseipdb API keys. The free tiers alone should have relatively high quotas for personal usage.

You are all set!

## Demonstration 
### 1. Plaintext Mode
Submitting a sample domain for analysis: `hackernoon.com`
![alt text](/img/image.png)

Submitting a sample IP address for analysis: `142.251.40.174`  google.com

VirusTotal and Abuseipdb section:
![alt text](/img/vt_ptmode.png)

Spur & Ipinfo section:
![alt text](/img/spur_ptmode.png)

### 2. Table Mode
Code will be under **osint_for_all_TABLED folder**

Improved readability in a table. However, may have issues copy n pasting to elsewhere.

**Here are the results:**
1. VT segment

![alt text](/img/table_vt.png)

2. Abuseipdb
 
![alt text](/img/table_abuse.png)

3. Spur & Ipinfo

![alt text](/img/table_ip.png)


## Notes
### VT API Limits
For the VT API Key, premium (org private user) API quota allowances are at 1000 lookups/day, 31k lookups/month.

### Urlscan
Urlscan API (org team) quotas: 100k private scans/day across the team account.

For URLSCAN, to check remaining quotas:

`curl -H "Content-Type: application/json" -H "API-Key: $apikey" "https://urlscan.io/user/quotas/" `

URLSCAN is selected as one of our tools for url scanning as it automatically collects from a few sources in addition to manual submissions:
1. OpenPhish AI-powered list of potential phishing sites: OpenPhish
2. PhishTank List of potential phishing sites: PhishTank
3. CertStream Suspicious domains observed on CertStream
4. Twitter URLs being tweeted / pasted by various Twitter users.
5. URLhaus Malware URL exchange by Abuse.ch: URLhaus


# Author
Developed by Davin Hong.

For any questions, please feel free to reach out at https://www.linkedin.com/in/davinhong/
