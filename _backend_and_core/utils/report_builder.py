import uuid
from datetime import datetime

def generate_final_report(raw_scan_data: dict):
    """
    Yeh function Orchestrator se raw data lega aur usko ek
    Enterprise-Level Report format me convert karega.
    """
    
    # Ek unique ID banana har report ke liye (Jaise Invoice number hota hai)
    report_id = f"REP-{uuid.uuid4().hex[:8].upper()}"
    
    # Current time nikalna
    scan_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    
    # Professional Report Format (JSON)
    enterprise_report = {
        "metadata": {
            "report_id": report_id,
            "scan_timestamp": scan_time,
            "engine_version": "PhishGuard Core v2.0 (with Tracer)", # Engine update kar diya
            "analyzer_status": "Success"
        },
        "target": {
            "url_scanned": raw_scan_data.get("url"),
            # 🔴 NAYI LINE: Yahan pe aayega Hacker ka aakhri (Asli) thikana
            "real_destination": raw_scan_data.get("real_destination", "No Redirect") 
        },
        "threat_intelligence": {
            "verdict": raw_scan_data.get("verdict"),        # Malicious, Suspicious, Safe
            "risk_score_percentage": raw_scan_data.get("risk_score"),
            "severity": "CRITICAL" if raw_scan_data.get("risk_score", 0) >= 70 else ("WARNING" if raw_scan_data.get("risk_score", 0) >= 40 else "INFO"),
            "threat_reason": raw_scan_data.get("threat_reason", "No specific threat reason identified.")
        },
        "threat_reason": raw_scan_data.get("threat_reason", "No specific threat reason identified."),
        "detailed_analysis": raw_scan_data.get("details", {}),
        "recommendation": generate_recommendation(raw_scan_data.get("verdict"))
    }
    
    return enterprise_report

def generate_recommendation(verdict: str):
    """Verdict ke hisaab se user ko kya karna chahiye (Actionable Advice)"""
    if verdict == "Malicious":
        return "IMMEDIATE ACTION REQUIRED: Block this URL in your firewall. Do not enter any credentials."
    elif verdict == "Suspicious":
        return "PROCEED WITH CAUTION: This URL shows risky behavior. Verify the sender before opening."
    else:
        return "SAFE: No immediate threats detected. Normal browsing allowed."