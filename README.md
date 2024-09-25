# All-in-One OSINT IP & URL & Domain Indicator Enrichment Toolsuite
## Apollo.py 
**An all in one tool for IP/URL/Domain analysis and enrichment.**

Tired of running the same URL/IP or domain indicator across different analysis platforms and tools manually? This tool allows you to run the same target across a multitude of analysis and reputation check platforms, allowing a seamless experience and a combined output with just one click.

**Tools in the suite:**
At the current stage, tool only uses API keys for VT and Urlscan.
1. VirusTotal - Scans IP address/URL/Domain for reputation checks
2. AbuseIPDB - IP enrichment
3. Urlscan.io - generates the URL site screenshots and dom snapshot links 
4. IPinfo - IP enrichment
5. Spur.us - IP enrichment
6. SiteReview - URL/Domain categorization checks (pending development)

## Usage
**Target:** Single IP address, URL or domain to investigate

A simple single command to run the tool `python3 apollo.py <target>`
Tool will automatically parse the input and determine the type of indicator it is, executing the appropriate modules relavant to the indicator type.

## Setting up
Install the relevant dependencies:
`pip install python-dotenv rich prettytable beautifulsoup4 tqdm`

Fill in the sample_env.txt with your API Keys and rename file to `.env`.

You are all set!

## Demonstration
Submitting a sample domain for analysis: `hackernoon.com`
![alt text](/img/image.png)

Submitting a sample IP address for analysis: `142.251.40.174`  google.com

VirusTotal and URLSCAN enrichment:
![alt text](/img/image-01.png)

Abuseipdb section:
![alt text](/img/image_abuseipdb.png)

Spur & Ipinfo section:
![alt text](/img/image_spur.png)

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


## Developments 1.0 - Table format
I was given the request to table every result from the IP enrichment, due to the volume of output. Definitely more readable in a table.

**Here are the results:**
1. VT segment

![alt text](/img/table_vt.png)

2. Abuseipdb
 
![alt text](/img/table_abuse.png)

3. Spur & Ipinfo

![alt text](/img/table_ip.png)

