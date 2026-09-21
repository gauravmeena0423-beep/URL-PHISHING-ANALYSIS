import requests
import os
import re

def scan_file_hash(file_hash: str, scan_type: str = "file"):
    """
    File/APK Hash ka VirusTotal se analysis:
    - MD5 / SHA1 / SHA256 hash supported
    - APK detection flag
    - Malware family names
    - Detection engines count
    
    scan_type: "file" | "apk"
    """
    
    # Hash validation (MD5=32, SHA1=40, SHA256=64)
    hash_clean = file_hash.strip().lower()
    if not re.match(r"^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$", hash_clean):
        return {"error": "Invalid hash format. Provide MD5 (32), SHA1 (40), or SHA256 (64) hex."}, 0
    
    VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
    if not VT_API_KEY or VT_API_KEY == "YOUR_DUMMY_KEY":
        return {"error": "VirusTotal API Key not configured"}, 0
    
    result = {
        "hash": hash_clean,
        "hash_type": "MD5" if len(hash_clean) == 32 else ("SHA1" if len(hash_clean) == 40 else "SHA256"),
        "scan_type": scan_type.upper(),
        "is_apk": scan_type == "apk",
        "detection_count": 0,
        "total_engines": 0,
        "detection_ratio": "0/0",
        "malware_families": [],
        "threat_labels": [],
        "file_type": "Unknown",
        "file_size": "Unknown",
        "first_seen": "Unknown",
        "last_seen": "Unknown",
        "verdict": "Unknown",
        "risk_score": 0
    }
    
    try:
        endpoint = f"https://www.virustotal.com/api/v3/files/{hash_clean}"
        headers = {"x-apikey": VT_API_KEY}
        
        response = requests.get(endpoint, headers=headers, timeout=10)
        
        if response.status_code == 404:
            result["verdict"] = "Not Found"
            result["note"] = "This hash was not found in VirusTotal database. Either clean or never scanned."
            return result, 0
        
        if response.status_code == 429:
            return {"error": "VirusTotal API rate limit reached. Try again in a minute."}, 0
        
        if response.status_code != 200:
            return {"error": f"VirusTotal API error: HTTP {response.status_code}"}, 0
        
        data = response.json()
        attrs = data["data"]["attributes"]
        
        # Analysis stats
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values())
        flagged = malicious + suspicious
        
        result["detection_count"] = flagged
        result["total_engines"] = total
        result["detection_ratio"] = f"{flagged}/{total}"
        result["stats"] = stats
        
        # File metadata
        result["file_type"] = attrs.get("type_description", attrs.get("magic", "Unknown"))
        result["file_size"] = attrs.get("size", "Unknown")
        
        # Dates
        if attrs.get("first_submission_date"):
            from datetime import datetime
            result["first_seen"] = datetime.utcfromtimestamp(attrs["first_submission_date"]).strftime("%Y-%m-%d")
        if attrs.get("last_analysis_date"):
            from datetime import datetime
            result["last_seen"] = datetime.utcfromtimestamp(attrs["last_analysis_date"]).strftime("%Y-%m-%d")
        
        # APK specific checks
        if scan_type == "apk" or "apk" in result["file_type"].lower() or "android" in result["file_type"].lower():
            result["is_apk"] = True
            result["scan_type"] = "APK"
        
        # Malware families (popular names from AV engines)
        malware_names = set()
        threat_labels = set()
        analysis_results = attrs.get("last_analysis_results", {})
        for engine, engine_data in analysis_results.items():
            if engine_data.get("category") in ["malicious", "suspicious"]:
                name = engine_data.get("result")
                if name:
                    # Normalize malware family name
                    parts = re.split(r'[./\\!]', name)
                    if len(parts) > 1:
                        malware_names.add(parts[-1].strip())
                    threat_labels.add(name.strip())
        
        result["malware_families"] = list(malware_names)[:5]  # Top 5
        result["threat_labels"] = list(threat_labels)[:8]  # Top 8 labels
        
        # Risk Score Calculation
        if total > 0:
            detection_percentage = (flagged / total) * 100
            if detection_percentage >= 50:
                risk_score = 100
            elif detection_percentage >= 25:
                risk_score = 85
            elif detection_percentage >= 10:
                risk_score = 65
            elif detection_percentage >= 5:
                risk_score = 45
            elif flagged > 0:
                risk_score = 30
            else:
                risk_score = 0
        else:
            risk_score = 0
        
        result["risk_score"] = risk_score
        
        # Verdict
        if risk_score >= 70:
            result["verdict"] = "Malicious"
        elif risk_score >= 30:
            result["verdict"] = "Suspicious"
        else:
            result["verdict"] = "Safe"
        
        return result, risk_score
        
    except Exception as e:
        return {"error": f"Scan failed: {str(e)}"}, 0
