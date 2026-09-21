from .extractors.lexical import extract_lexical_features
from .extractors.network import extract_network_features
from .threat_intel.virustotal import check_virustotal
from .threat_intel.google_safebrowsing import check_google_safebrowsing
from .ai_ml_models.predictor import get_ml_prediction
from utils.url_tracer import get_final_url
from .threat_intel.urlhaus import check_urlhaus
from .threat_intel.abuseipdb import check_abuseipdb
from .threat_intel.shodan_api import check_shodan


def scan_url(original_url: str):
    print(f"🔍 Initial URL: {original_url}")
    
    # 1. Tracer (SAFE UNPACKING FIX: Ab crash nahi hoga chahe 2 value aaye ya 3)
    tracer_result = get_final_url(original_url)
    if len(tracer_result) == 3:
        final_url, was_redirected, tracer_error = tracer_result
    else:
        final_url, was_redirected = tracer_result
        tracer_error = None  # Agar teesri value nahi aayi, toh isko None maan lenge
        
    print(f"📍 Final Destination URL: {final_url}")
    
    lex_data, lex_risk = extract_lexical_features(final_url)
    net_data, net_risk = extract_network_features(final_url)
    
    if was_redirected:
        lex_risk += 15 
        
    # Agar Timeout ya Crash hua, toh hacker chupa raha hai = Penalty +30
    if tracer_error:
        lex_risk += 30 
        
    vt_data, vt_risk = check_virustotal(final_url)
    gsb_is_bad, gsb_risk = check_google_safebrowsing(final_url)
    uh_is_bad, uh_risk = check_urlhaus(final_url)
    abuse_data, abuse_risk = check_abuseipdb(final_url)
    
    resolved_ip = net_data.get("resolved_ip", "Unknown")
    shodan_data, shodan_risk = check_shodan(resolved_ip)
    
    ml_risk = get_ml_prediction(lex_data, net_data)
    
    total_score = (
        (lex_risk * 0.10) +     
        (net_risk * 0.10) +     
        (ml_risk * 0.15) +      
        (vt_risk * 0.20) +      
        (gsb_risk * 0.15) +
        (uh_risk * 0.15) +      
        (abuse_risk * 0.10) +
        (shodan_risk * 0.05)    
    )
    
    # AI OVERRULE (False Positive Fix)
    if vt_risk == 0 and gsb_risk == 0 and not uh_is_bad and lex_risk < 20:
        total_score = min(total_score, 15)  
    
    # CRITICAL OVERRIDE (Hacker Block)
    if uh_is_bad:
        total_score = 100  
    elif abuse_risk >= 50 or lex_risk >= 80:
        total_score = max(total_score, 90)  
    elif lex_risk >= 50:
        total_score = max(total_score, 65)  
    
    # Timeout/Error Overrule
    if tracer_error and total_score < 40:
        total_score = 45 
    
    final_risk_score = round(min(total_score, 100))
    
    # 🔴 NAYA LOGIC: THREAT REASON GENERATOR
    threat_reason = "No immediate threats detected. URL seems clean."
    
    if final_risk_score >= 70:
        verdict = "Malicious"
        if uh_is_bad: threat_reason = "Active Malware found in URLhaus Database."
        elif gsb_is_bad: threat_reason = "Flagged by Google Safe Browsing for phishing/malware."
        elif lex_data.get("is_logger"): threat_reason = "IP Logger detected (Attempts to steal your location/IP)."
        elif lex_data.get("is_evasion"): threat_reason = "Evasion Wall detected (Hacker attempting to block security scanners)."
        elif lex_data.get("is_webhook_or_tunnel"): threat_reason = "Data Drop Site detected (High risk of credential theft)."
        elif lex_data.get("count_at") > 0: threat_reason = "URL Cloaking detected using '@' symbol."
        elif ml_risk > 80: threat_reason = "AI Engine detected high-confidence phishing patterns."
        else: threat_reason = "Multiple high-risk factors detected across security layers."
    
    elif final_risk_score >= 40:
        verdict = "Suspicious"
        if tracer_error: threat_reason = f"Security scan blocked by target server ({tracer_error})."
        elif was_redirected: threat_reason = "Hidden redirects detected. Final destination is risky."
        elif abuse_risk > 0: threat_reason = "Associated IP has been reported for abuse."
        else: threat_reason = "Shows unusual or risky behavior. Proceed with caution."
    else:
        verdict = "Safe"
        
    report = {
        "url": original_url,
        "real_destination": final_url, 
        "verdict": verdict,
        "risk_score": final_risk_score,
        "threat_reason": threat_reason, # 🔴 Reason Frontend ko bhej diya
        "details": {
            "lexical_analysis": lex_data,
            "network_analysis": net_data,
            "virustotal": vt_data,
            "google_safe_browsing": "Blocked" if gsb_is_bad else "Clean",
            "urlhaus": "Malware Found" if uh_is_bad else "Clean",
            "abuseipdb": abuse_data,
            "shodan": shodan_data,            
            "ml_ai_score": ml_risk,
            "system_errors": tracer_error if tracer_error else "None"
        }
    }
    
    return report