import whois
import socket
from urllib.parse import urlparse
from datetime import datetime

def extract_network_features(url: str):
    domain = urlparse(url).netloc.split(':')[0]
    
    # 🔴 1. NSLOOKUP (Domain to IP Resolution)
    try:
        resolved_ip = socket.gethostbyname(domain)
    except Exception:
        resolved_ip = "Unknown"

    # 🔴 2. WHOIS DATA (Registration Info)
    try:
        domain_info = whois.whois(url)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list): creation_date = creation_date[0]
        
        expiration_date = domain_info.expiration_date
        if isinstance(expiration_date, list): expiration_date = expiration_date[0]
        
        if creation_date:
            days_old = (datetime.now() - creation_date).days
            risk_score = 40 if days_old < 30 else 0
        else:
            days_old = -1
            risk_score = 10

        network_details = {
            "resolved_ip": resolved_ip,
            "days_old": days_old,
            "registrar": domain_info.registrar or "Unknown",
            "creation_date": creation_date.strftime("%Y-%m-%d") if creation_date else "Unknown",
            "expiration_date": expiration_date.strftime("%Y-%m-%d") if expiration_date else "Unknown",
            "registrant_org": domain_info.org or domain_info.name or "Privacy Protected",
            "registrant_country": domain_info.country or "Hidden"
        }
        return network_details, risk_score
            
    except Exception:
        return {"error": "WHOIS Protected/Invalid", "resolved_ip": resolved_ip, "days_old": -1}, 20