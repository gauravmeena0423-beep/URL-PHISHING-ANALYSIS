import requests
import os
import socket
from urllib.parse import urlparse
import re

def check_abuseipdb(url: str):
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key: 
        return {"error": "Missing API Key"}, 0
    
    # 1. URL se website ka naam nikalo
    domain = urlparse(url).netloc.split(':')[0] 
    if not domain: 
        return {"error": "Invalid URL"}, 0
    
    try:
        # 2. Check karo ki wo pehle se IP hai ya Website naam hai
        if re.match(r"\d+\.\d+\.\d+\.\d+", domain):
            ip_to_check = domain
        else:
            # Website naam ko IP mein badlo (DNS Resolution)
            ip_to_check = socket.gethostbyname(domain)
    except Exception:
        return {"error": "DNS Resolution Failed"}, 0

    # 3. AbuseIPDB se pucho
    endpoint = "https://api.abuseipdb.com/api/v2/check"
    querystring = {'ipAddress': ip_to_check, 'maxAgeInDays': '90'}
    headers = {'Accept': 'application/json', 'Key': api_key}
    
    try:
        response = requests.request(method='GET', url=endpoint, headers=headers, params=querystring)
        data = response.json()
        score = data['data']['abuseConfidenceScore'] # Yeh 0 se 100 tak score deta hai
        return {"ip": ip_to_check, "score": score}, score
    except Exception as e:
        return {"error": str(e)}, 0