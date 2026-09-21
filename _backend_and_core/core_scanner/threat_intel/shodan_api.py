import shodan
import os

def check_shodan(ip: str):
    if ip == "Unknown" or not ip:
        return {"error": "No IP resolved"}, 0
        
    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
    if not SHODAN_API_KEY: 
        return {"error": "Missing Shodan API Key"}, 0
        
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        host = api.host(ip)
        
        details = {
            "isp": host.get("isp", "Unknown"),
            "org": host.get("org", "Unknown"),
            "ports": host.get("ports", [])
        }
        
        # Agar Server pe bohot zyada ports open hain (Hackers aksar aaisa karte hain)
        risk = 20 if len(details["ports"]) > 4 else 0
        return details, risk
        
    except shodan.APIError as e:
        return {"error": "No Shodan record found"}, 0
    except Exception:
        return {"error": "Shodan Scan Failed"}, 0