import requests
import base64
import os

def check_virustotal(url: str):
    # .env file se API key lena (Maan lo abhi None hai)
    VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "YOUR_DUMMY_KEY")
    
    if VT_API_KEY == "YOUR_DUMMY_KEY":
        return {"error": "API Key Missing"}, 0

    try:
        # VirusTotal URL ko Base64 encode mangta hai
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        
        headers = {"x-apikey": VT_API_KEY}
        response = requests.get(endpoint, headers=headers)
        
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            malicious_votes = stats['malicious'] + stats['suspicious']
            
            # Agar 2 se zyada AV ne block kiya toh 100% danger
            risk_score = min(malicious_votes * 25, 100) 
            return stats, risk_score
        else:
            return {"error": "URL not found in VT or API limit reached"}, 0
            
    except Exception as e:
        return {"error": str(e)}, 0