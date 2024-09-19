# Threat Intelligence Tools Collection
## Osint_for_all.py 
**An all in one tool for IP/URL/Domain analysis and enrichment.**

Tired of running the same URL/IP or domain indicator across different analysis platforms and tools manually? This tool allows you to run the same target across a multitude of analysis and reputation check platforms, allowing a seamless experience and a combined output with just one click.

**Tools in the suite:**
1. VirusTotal - Scans IP address/URL/Domain for reputation checks
2. AbuseIPDB - IP enrichment
3. Urlscan.io - generates the URL site screenshots and dom snapshot links 
4. IPinfo - IP enrichment
5. Spur.us - IP enrichment
6. SiteReview - URL/Domain categorization checks (pending)

## Usage
**Target:** IP address, URL or domain to investigate

A simple single command to run the tool `python3 osint_for_all.py <target>`

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