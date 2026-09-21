import requests
import socket
import os
import re

def scan_ip_address(ip: str):
    """
    Direct IP Address ka full analysis:
    1. ipapi.co se Geolocation (Free, no key needed)
    2. AbuseIPDB se Abuse Score
    3. Shodan se Open Ports
    4. Reverse DNS Lookup
    """
    
    # Validate karo ki ye sach mein IP hai
    ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    if not ip_pattern.match(ip):
        return None, 0  # Invalid IP
    
    result = {
        "ip": ip,
        "geolocation": {},
        "reverse_dns": "N/A",
        "abuse_score": 0,
        "shodan_ports": [],
        "isp": "Unknown",
        "org": "Unknown",
        "asn": "Unknown"
    }
    risk_score = 0
    
    # --- 1. GEOLOCATION (ipapi.co - Free) ---
    try:
        geo_response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,reverse", timeout=5)
        if geo_response.status_code == 200:
            geo_data = geo_response.json()
            if geo_data.get("status") == "success":
                result["geolocation"] = {
                    "country": geo_data.get("country", "Unknown"),
                    "region": geo_data.get("regionName", "Unknown"),
                    "city": geo_data.get("city", "Unknown"),
                }
                result["isp"] = geo_data.get("isp", "Unknown")
                result["org"] = geo_data.get("org", "Unknown")
                result["asn"] = geo_data.get("as", "Unknown")
                result["reverse_dns"] = geo_data.get("reverse", "N/A")
    except Exception:
        pass  # Graceful fail
    
    # --- 2. ABUSEIPDB CHECK ---
    try:
        api_key = os.getenv("ABUSEIPDB_API_KEY")
        if api_key:
            endpoint = "https://api.abuseipdb.com/api/v2/check"
            querystring = {"ipAddress": ip, "maxAgeInDays": "90"}
            headers = {"Accept": "application/json", "Key": api_key}
            abuse_response = requests.get(endpoint, headers=headers, params=querystring, timeout=5)
            if abuse_response.status_code == 200:
                abuse_data = abuse_response.json()
                result["abuse_score"] = abuse_data["data"]["abuseConfidenceScore"]
                result["total_reports"] = abuse_data["data"].get("totalReports", 0)
                result["usage_type"] = abuse_data["data"].get("usageType", "Unknown")
                result["is_whitelisted"] = abuse_data["data"].get("isWhitelisted", False)
                
                # Risk calculation
                score = result["abuse_score"]
                if score >= 80:
                    risk_score += 80
                elif score >= 50:
                    risk_score += 50
                elif score >= 20:
                    risk_score += 30
                elif score > 0:
                    risk_score += 15
    except Exception:
        pass
    
    # --- 3. SHODAN OPEN PORTS ---
    try:
        SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
        if SHODAN_API_KEY:
            import shodan
            api = shodan.Shodan(SHODAN_API_KEY)
            host = api.host(ip)
            result["shodan_ports"] = host.get("ports", [])
            result["isp"] = result["isp"] or host.get("isp", "Unknown")
            result["org"] = result["org"] or host.get("org", "Unknown")
            
            # Zyada open ports = suspicious
            if len(result["shodan_ports"]) > 5:
                risk_score += 20
    except Exception:
        pass
    
    # --- 4. PRIVATE/RESERVED IP CHECK ---
    private_ranges = ["10.", "192.168.", "172.16.", "127."]
    if any(ip.startswith(r) for r in private_ranges):
        result["is_private"] = True
        return result, 0  # Private IPs always safe
    result["is_private"] = False
    
    final_risk = min(risk_score, 100)
    
    # Verdict
    if final_risk >= 70:
        verdict = "Malicious"
    elif final_risk >= 30:
        verdict = "Suspicious"
    else:
        verdict = "Safe"
    
    result["verdict"] = verdict
    result["risk_score"] = final_risk
    
    return result, final_risk
