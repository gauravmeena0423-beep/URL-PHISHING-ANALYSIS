import re
from urllib.parse import urlparse

def extract_lexical_features(url: str):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lower()
    
    # 1. IP LOGGERS
    ip_loggers = ["iplogger", "grabify", "blasze", "ps3cfw", "leancoding.co", "stopify"]

    # 2. EVASION WALLS (Click-Walls / Captcha Walls used by hackers)
    evasion_walls = ["encurtador.dev", "l1nq.com", "ouo.io", "shorte.st", "adf.ly"]

    # 3. URL SHORTENERS 
    url_shorteners = [
        "bit.ly", "tinyurl.com", "cutt.ly", "short.io", "rebrandly", "bl.ink", 
        "t2m.io", "is.gd", "v.gd", "ow.ly", "t.co", "s.id", "rb.gy", "tiny.cc", "urlshort.dev"
    ]

    # 4. WEBHOOKS & TUNNELS (Password Stealers)
    data_drop_sites = ["webhook.site", "requestbin", "beeceptor", "ngrok.io", "ngrok-free.app", "serveo.net", "loca.lt"]

    # Check mapping
    features = {
        "url_length": len(url),
        "domain_length": len(domain),
        "has_ip": 1 if re.match(r"\d+\.\d+\.\d+\.\d+", domain) else 0,
        "count_at": url.count("@"),
        "count_hyphen": domain.count("-"),
        "is_https": 1 if parsed_url.scheme == "https" else 0,
        "is_logger": 1 if any(x in domain for x in ip_loggers) else 0,
        "is_evasion": 1 if any(x in domain for x in evasion_walls) else 0, 
        "is_shortener": 1 if any(x in domain for x in url_shorteners) else 0,
        "is_webhook_or_tunnel": 1 if any(x in domain for x in data_drop_sites) else 0,
        "is_webhook": 1 if any(x in domain for x in data_drop_sites) else 0
    }
    
    risk_score = 0
    
    if features["has_ip"]: 
        risk_score += 30      
        
    # 🔴 THE ULTIMATE FIX: '@' Symbol Hacker Masking! Penalty = 80
    if features["count_at"] > 0: 
        risk_score += 80 
        
    if features["count_hyphen"] > 2: 
        risk_score += 10 
        
    if features["url_length"] > 75: 
        risk_score += 10  
    
    # 🔴 AGGRESSIVE HACKER BLOCKING RULES
    if features["is_webhook_or_tunnel"]:
        risk_score += 90  
    if features["is_logger"]:
        risk_score += 80  
    if features["is_evasion"]: 
        risk_score += 80  
    if features["is_shortener"]:
        risk_score += 30  
        
    return features, min(risk_score, 100)