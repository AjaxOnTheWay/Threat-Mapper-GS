import os
import urllib.parse
import httpx
from dotenv import load_dotenv

# Load variables from the .env file
load_dotenv()
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
URLHAUS_API_KEY = os.getenv("URLHAUS_API_KEY")
MISP_URL = os.getenv("MISP_URL")
MISP_AUTH_KEY = os.getenv("MISP_AUTH_KEY")
HIBP_API_KEY = os.getenv("HIBP_API_KEY")

async def fetch_virustotal(ioc_value: str, ioc_type: str) -> dict:
    """Asynchronously queries the VirusTotal v3 API."""
    if not VT_API_KEY or VT_API_KEY == "your_vt_api_key_here":
        print("Warning: VirusTotal API key not configured in .env", flush=True)
        return {"is_flagged": False}

    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
    }
    
    if ioc_type == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc_value}"
    elif ioc_type == "hash":
        url = f"https://www.virustotal.com/api/v3/files/{ioc_value}"
    else:
        return {"is_flagged": False}

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, headers=headers, timeout=10.0)
            if response.status_code == 429:
                print("[WARNING] VirusTotal API Rate limit hit. Using safe fallback.", flush=True)
                return {"is_flagged": False, "error": "QuotaExceeded"}
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious_votes = stats.get("malicious", 0)
                return {"is_flagged": malicious_votes > 0}
            else:
                return {"is_flagged": False}
        except Exception as e:
            print(f"VT Connection Exception: {str(e)}", flush=True)
            return {"is_flagged": False}

async def fetch_abuseipdb(ioc_value: str, ioc_type: str) -> dict:
    """Asynchronously queries the AbuseIPDB v2 API."""
    if ioc_type != "ip":
        return {"is_flagged": False}
        
    if not ABUSEIPDB_API_KEY or ABUSEIPDB_API_KEY == "your_abuseipdb_key_here":
        print("Warning: AbuseIPDB API key not configured in .env", flush=True)
        return {"is_flagged": False}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY
    }
    params = {
        "ipAddress": ioc_value,
        "maxAgeInDays": "90"
    }

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, headers=headers, params=params, timeout=10.0)
            if response.status_code == 429:
                print("[WARNING] AbuseIPDB API Rate limit hit. Using safe fallback.", flush=True)
                return {"is_flagged": False, "error": "QuotaExceeded"}
            if response.status_code == 200:
                data = response.json()
                score = data.get("data", {}).get("abuseConfidenceScore", 0)
                return {"is_flagged": score > 50}
            else:
                return {"is_flagged": False}
        except Exception as e:
            print(f"AbuseIPDB Connection Exception: {str(e)}", flush=True)
            return {"is_flagged": False}

async def fetch_urlhaus(ioc_value: str, ioc_type: str) -> dict:
    """
    Asynchronously queries the URLhaus API using URL-encoded form data.
    Supports IPs, domains, hashes, and URLs.
    """
    if ioc_type not in ["ip", "domain", "url", "hash"]:
        return {"is_flagged": False}

    headers = {}
    if URLHAUS_API_KEY and URLHAUS_API_KEY != "your_urlhaus_key_here":
        headers["Auth-Key"] = URLHAUS_API_KEY

    # Determine endpoint and payload based on IOC type
    if ioc_type in ["ip", "domain"]:
        url = "https://urlhaus-api.abuse.ch/v1/host/"
        data = {"host": ioc_value}
    elif ioc_type == "url":
        url = "https://urlhaus-api.abuse.ch/v1/url/"
        data = {"url": ioc_value}
    elif ioc_type == "hash":
        url = "https://urlhaus-api.abuse.ch/v1/payload/"
        if len(ioc_value) == 32:
            data = {"md5_hash": ioc_value}
        elif len(ioc_value) == 64:
            data = {"sha256_hash": ioc_value}
        else:
            return {"is_flagged": False}

    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(url, headers=headers, data=data, timeout=10.0)
            if response.status_code == 429:
                return {"is_flagged": False, "error": "QuotaExceeded"}
                
            if response.status_code == 200:
                result = response.json()
                # URLhaus returns query_status: "ok" if it found a malicious record
                if result.get("query_status") == "ok":
                    return {"is_flagged": True}
                else:
                    return {"is_flagged": False}
            else:
                return {"is_flagged": False}
        except Exception as e:
            print(f"URLhaus Connection Exception: {str(e)}", flush=True)
            return {"is_flagged": False}

async def fetch_misp(ioc_value: str, ioc_type: str) -> dict:
    """
    Asynchronously queries a local or remote MISP instance via its REST API.
    """
    if not MISP_URL or MISP_URL == "https://your-misp-instance.com" or not MISP_AUTH_KEY:
        print("Warning: MISP credentials not configured in .env", flush=True)
        return {"is_flagged": False}

    base_url = MISP_URL.rstrip('/')
    url = f"{base_url}/attributes/restSearch"
    
    headers = {
        "Authorization": MISP_AUTH_KEY,
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    
    # MISP restSearch expects a JSON payload
    payload = {
        "value": ioc_value,
        "returnFormat": "json"
    }

    # Verify is set to False to prevent crashes with self-signed MISP certificates
    async with httpx.AsyncClient(verify=False) as client: 
        try:
            response = await client.post(url, headers=headers, json=payload, timeout=10.0)
            if response.status_code == 200:
                data = response.json()
                # MISP groups results under 'response' -> 'Attribute'
                attributes = data.get("response", {}).get("Attribute", [])
                return {"is_flagged": len(attributes) > 0}
            else:
                return {"is_flagged": False}
        except Exception as e:
            print(f"MISP Connection Exception: {str(e)}", flush=True)
            return {"is_flagged": False}

async def fetch_hibp(ioc_value: str, ioc_type: str) -> dict:
    """
    Asynchronously queries Have I Been Pwned (v3) API for breached emails.
    """
    if ioc_type != "email":
        return {"is_flagged": False}
        
    if not HIBP_API_KEY or HIBP_API_KEY == "your_haveibeenpwned_key":
        print("Warning: HIBP API key not configured in .env", flush=True)
        return {"is_flagged": False}

    # HIBP requires url-encoding the email address for the URL path
    encoded_email = urllib.parse.quote(ioc_value)
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{encoded_email}?truncateResponse=false"
    
    headers = {
        "hibp-api-key": HIBP_API_KEY,
        "user-agent": "ThreatMapper-OSINT-Engine"
    }

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, headers=headers, timeout=10.0)
            if response.status_code == 429:
                return {"is_flagged": False, "error": "QuotaExceeded"}
            elif response.status_code == 200:
                breaches = response.json()
                return {"is_flagged": len(breaches) > 0}
            elif response.status_code == 404:
                # 404 means no breaches were found for the email (Safe)
                return {"is_flagged": False}
            else:
                return {"is_flagged": False}
        except Exception as e:
            print(f"HIBP Connection Exception: {str(e)}", flush=True)
            return {"is_flagged": False}