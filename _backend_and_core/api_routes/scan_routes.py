from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from database.db_config import get_db
from database.models import ScanHistory

# Core Logic imports
from core_scanner.orchestrator import scan_url 
from core_scanner.threat_intel.ip_scanner import scan_ip_address
from core_scanner.threat_intel.hash_scanner import scan_file_hash
from utils.report_builder import generate_final_report
import uuid
from datetime import datetime

router = APIRouter()

# --- Request Models ---
class URLRequest(BaseModel):
    url: str

class IPRequest(BaseModel):
    ip: str

class HashRequest(BaseModel):
    hash: str
    scan_type: str = "file"  # "file" or "apk"


# =====================================================================
# ROUTE 1: URL Scan (Existing - Preserved)
# =====================================================================
@router.post("/check-url")
async def check_url(request: URLRequest, db: Session = Depends(get_db)):
    url = request.url
    
    raw_scan_data = scan_url(url)
    enterprise_report = generate_final_report(raw_scan_data)
    
    new_scan_record = ScanHistory(
        url=url,
        verdict=enterprise_report["threat_intelligence"]["verdict"],
        risk_score=enterprise_report["threat_intelligence"]["risk_score_percentage"]
    )
    db.add(new_scan_record)
    db.commit()
    db.refresh(new_scan_record)
    
    return enterprise_report


# =====================================================================
# ROUTE 2: IP Address Scan (NEW)
# =====================================================================
@router.post("/check-ip")
async def check_ip(request: IPRequest, db: Session = Depends(get_db)):
    ip = request.ip.strip()
    
    # IP Scanner run karo
    ip_data, risk_score = scan_ip_address(ip)
    
    if ip_data is None:
        return {
            "error": "Invalid IP address format.",
            "metadata": {"scan_type": "IP"},
            "target": {"ip_scanned": ip},
            "threat_intelligence": {"verdict": "Error", "risk_score_percentage": 0}
        }
    
    # Verdict
    verdict = ip_data.get("verdict", "Unknown")
    
    # Threat reason generate karo
    if verdict == "Malicious":
        threat_reason = f"IP has {ip_data.get('abuse_score', 0)}% abuse confidence score on AbuseIPDB."
    elif verdict == "Suspicious":
        threat_reason = f"IP shows suspicious activity. Abuse score: {ip_data.get('abuse_score', 0)}%."
    else:
        threat_reason = "No malicious activity detected for this IP address."
    
    # Recommendation
    if verdict == "Malicious":
        recommendation = "BLOCK IMMEDIATELY: This IP is known for malicious activity. Do not connect to it."
    elif verdict == "Suspicious":
        recommendation = "CAUTION: This IP has some suspicious reports. Avoid sharing sensitive data."
    else:
        recommendation = "SAFE: This IP appears clean. No known malicious activity."
    
    # Open ports mein dangerous ones check karo
    dangerous_ports = {22: "SSH", 23: "Telnet", 3389: "RDP", 4444: "Metasploit", 8080: "Proxy", 1080: "SOCKS Proxy"}
    detected_dangerous = {}
    for port in ip_data.get("shodan_ports", []):
        if port in dangerous_ports:
            detected_dangerous[port] = dangerous_ports[port]
    
    # Enterprise Report format
    report = {
        "metadata": {
            "report_id": f"IP-{uuid.uuid4().hex[:8].upper()}",
            "scan_timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "engine_version": "PhishGuard IP Scanner v1.0",
            "scan_type": "IP_ADDRESS"
        },
        "target": {
            "ip_scanned": ip,
            "reverse_dns": ip_data.get("reverse_dns", "N/A"),
            "is_private": ip_data.get("is_private", False)
        },
        "threat_intelligence": {
            "verdict": verdict,
            "risk_score_percentage": risk_score,
            "severity": "CRITICAL" if risk_score >= 70 else ("WARNING" if risk_score >= 30 else "INFO"),
            "threat_reason": threat_reason
        },
        "threat_reason": threat_reason,
        "detailed_analysis": {
            "geolocation": ip_data.get("geolocation", {}),
            "isp": ip_data.get("isp", "Unknown"),
            "org": ip_data.get("org", "Unknown"),
            "asn": ip_data.get("asn", "Unknown"),
            "abuse_score": ip_data.get("abuse_score", 0),
            "total_reports": ip_data.get("total_reports", 0),
            "usage_type": ip_data.get("usage_type", "Unknown"),
            "is_whitelisted": ip_data.get("is_whitelisted", False),
            "open_ports": ip_data.get("shodan_ports", []),
            "dangerous_ports": detected_dangerous
        },
        "recommendation": recommendation
    }
    
    # Database save (URL field mein IP store karte hain)
    try:
        new_scan_record = ScanHistory(
            url=f"IP:{ip}",
            verdict=verdict,
            risk_score=risk_score
        )
        db.add(new_scan_record)
        db.commit()
    except Exception:
        pass
    
    return report


# =====================================================================
# ROUTE 3: File Hash / APK Hash Scan (NEW)
# =====================================================================
@router.post("/check-hash")
async def check_hash(request: HashRequest, db: Session = Depends(get_db)):
    file_hash = request.hash.strip()
    scan_type = request.scan_type  # "file" or "apk"
    
    # Hash Scanner run karo
    hash_data, risk_score = scan_file_hash(file_hash, scan_type)
    
    if "error" in hash_data:
        return {
            "error": hash_data["error"],
            "metadata": {"scan_type": scan_type.upper()},
            "target": {"hash_scanned": file_hash},
            "threat_intelligence": {"verdict": "Error", "risk_score_percentage": 0}
        }
    
    verdict = hash_data.get("verdict", "Unknown")
    is_apk = hash_data.get("is_apk", False)
    
    # Threat reason
    detection_ratio = hash_data.get("detection_ratio", "0/0")
    malware_families = hash_data.get("malware_families", [])
    
    if verdict == "Malicious":
        family_str = f" ({', '.join(malware_families[:2])})" if malware_families else ""
        threat_reason = f"Detected by {detection_ratio} security engines{family_str}."
    elif verdict == "Suspicious":
        threat_reason = f"Flagged by {detection_ratio} engines as suspicious."
    elif verdict == "Not Found":
        threat_reason = "Hash not found in VirusTotal database. May be clean or unscanned."
    else:
        threat_reason = f"No detections found by {hash_data.get('total_engines', 0)} security engines."
    
    # Recommendation
    if verdict == "Malicious":
        item = "APK/Android app" if is_apk else "file"
        recommendation = f"DANGER: Do NOT install/execute this {item}. It contains malware."
    elif verdict == "Suspicious":
        recommendation = "CAUTION: This file/APK is flagged by some engines. Treat as untrusted."
    elif verdict == "Not Found":
        recommendation = "UNKNOWN: Hash not in database. If from untrusted source, treat as suspicious."
    else:
        recommendation = "SAFE: No malware detected. File appears clean based on available intelligence."
    
    report = {
        "metadata": {
            "report_id": f"HASH-{uuid.uuid4().hex[:8].upper()}",
            "scan_timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "engine_version": "PhishGuard Hash Scanner v1.0",
            "scan_type": "APK_HASH" if is_apk else "FILE_HASH"
        },
        "target": {
            "hash_scanned": file_hash,
            "hash_type": hash_data.get("hash_type", "Unknown"),
            "is_apk": is_apk,
            "file_type": hash_data.get("file_type", "Unknown"),
            "file_size": hash_data.get("file_size", "Unknown")
        },
        "threat_intelligence": {
            "verdict": verdict,
            "risk_score_percentage": risk_score,
            "severity": "CRITICAL" if risk_score >= 70 else ("WARNING" if risk_score >= 30 else "INFO"),
            "threat_reason": threat_reason
        },
        "threat_reason": threat_reason,
        "detailed_analysis": {
            "detection_ratio": detection_ratio,
            "detection_count": hash_data.get("detection_count", 0),
            "total_engines": hash_data.get("total_engines", 0),
            "detection_stats": hash_data.get("stats", {}),
            "malware_families": malware_families,
            "threat_labels": hash_data.get("threat_labels", []),
            "first_seen": hash_data.get("first_seen", "Unknown"),
            "last_seen": hash_data.get("last_seen", "Unknown"),
            "is_apk": is_apk
        },
        "recommendation": recommendation
    }
    
    # Database save
    try:
        prefix = "APK" if is_apk else "HASH"
        new_scan_record = ScanHistory(
            url=f"{prefix}:{file_hash[:16]}...",
            verdict=verdict,
            risk_score=risk_score
        )
        db.add(new_scan_record)
        db.commit()
    except Exception:
        pass
    
    return report


# =====================================================================
# ROUTE 4: History (Existing - Preserved)
# =====================================================================
@router.get("/history")
async def get_scan_history(db: Session = Depends(get_db)):
    records = db.query(ScanHistory).order_by(ScanHistory.id.desc()).limit(20).all()
    return records