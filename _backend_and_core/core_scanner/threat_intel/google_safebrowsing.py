import requests
import os

def check_google_safebrowsing(url: str):
    GSB_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "YOUR_DUMMY_KEY")
    
    if GSB_API_KEY == "YOUR_DUMMY_KEY":
        return False, 0 # Key nahi hai toh safe maan lo
        
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}"
    payload = {
        "client": {"clientId": "PhishGuard", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    
    try:
        response = requests.post(endpoint, json=payload)
        data = response.json()
        
        # Agar koi match milta hai, matlab Google ne block kiya hai
        if "matches" in data:
            return True, 100 # 100% Danger
        return False, 0
        
    except Exception as e:
        return False, 0