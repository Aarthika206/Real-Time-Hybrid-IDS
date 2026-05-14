# web_threat_detector.py
import requests
import hashlib
import os
import json
from config import VIRUSTOTAL_API_KEY, SAFE_BROWSING_API_KEY

VT_URL_SCAN    = "https://www.virustotal.com/api/v3/urls"
VT_FILE_SCAN   = "https://www.virustotal.com/api/v3/files"
GSB_URL        = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

HEADERS_VT = {
    "x-apikey": VIRUSTOTAL_API_KEY,
    "Content-Type": "application/x-www-form-urlencoded"
}

# ── Check URL against VirusTotal ─────────────────────────────
def check_url_virustotal(url):
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            timeout=10
        )
        if resp.status_code == 200:
            data  = resp.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious  = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total      = sum(stats.values())
            return {
                "url"        : url,
                "malicious"  : malicious,
                "suspicious" : suspicious,
                "total"      : total,
                "is_threat"  : malicious > 0 or suspicious > 2,
                "source"     : "VirusTotal"
            }
    except Exception as e:
        return {"url": url, "error": str(e), "is_threat": False}
    return {"url": url, "is_threat": False}

# ── Submit new URL to VirusTotal for scanning ────────────────
def submit_url_virustotal(url):
    try:
        resp = requests.post(
            VT_URL_SCAN,
            headers=HEADERS_VT,
            data=f"url={url}",
            timeout=10
        )
        return resp.status_code == 200
    except:
        return False

# ── Check URL against Google Safe Browsing ───────────────────
def check_phishing_google(url):
    try:
        payload = {
            "client": {"clientId": "HybridIDS", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes"      : ["MALWARE", "SOCIAL_ENGINEERING",
                                      "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes"    : ["ANY_PLATFORM"],
                "threatEntryTypes" : ["URL"],
                "threatEntries"    : [{"url": url}]
            }
        }
        resp = requests.post(
            f"{GSB_URL}?key={SAFE_BROWSING_API_KEY}",
            json=payload,
            timeout=10
        )
        if resp.status_code == 200:
            data      = resp.json()
            is_threat = "matches" in data and len(data["matches"]) > 0
            threat_type = data["matches"][0]["threatType"] if is_threat else "None"
            return {
                "url"        : url,
                "is_threat"  : is_threat,
                "threat_type": threat_type,
                "source"     : "Google Safe Browsing"
            }
    except Exception as e:
        return {"url": url, "error": str(e), "is_threat": False}
    return {"url": url, "is_threat": False}

# ── Check file hash against VirusTotal ──────────────────────
def check_file_virustotal(filepath):
    try:
        with open(filepath, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            timeout=10
        )
        if resp.status_code == 200:
            data  = resp.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            return {
                "file"      : filepath,
                "hash"      : file_hash,
                "malicious" : malicious,
                "is_threat" : malicious > 0,
                "source"    : "VirusTotal"
            }
        elif resp.status_code == 404:
            return {"file": filepath, "hash": file_hash,
                    "is_threat": False, "note": "Not in VT database"}
    except Exception as e:
        return {"file": filepath, "error": str(e), "is_threat": False}
    return {"file": filepath, "is_threat": False}

# ── Combined check (URL goes through both APIs) ──────────────
def full_url_check(url):
    vt_result  = check_url_virustotal(url)
    gsb_result = check_phishing_google(url)
    is_threat  = vt_result.get("is_threat", False) or gsb_result.get("is_threat", False)
    return {
        "url"         : url,
        "is_threat"   : is_threat,
        "virustotal"  : vt_result,
        "safe_browsing": gsb_result
    }