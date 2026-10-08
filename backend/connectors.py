import os
import httpx
from dotenv import load_dotenv

# Load variables from the .env file
load_dotenv()
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

async def fetch_virustotal(ioc_value: str, ioc_type: str) -> dict:
    """
    Asynchronously queries the VirusTotal v3 API.
    Returns a dictionary matching the expected structure for the scoring engine.
    """
    if not VT_API_KEY or VT_API_KEY == "your_vt_api_key_here":
        print("Warning: VirusTotal API key not configured in .env", flush=True)
        return {"is_flagged": False}

    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
    }
    
    # Route to the correct VT endpoint based on type
    if ioc_type == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc_value}"
    elif ioc_type == "hash":
        url = f"https://www.virustotal.com/api/v3/files/{ioc_value}"
    else:
        return {"is_flagged": False}

    # Open an async HTTP session
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, headers=headers, timeout=10.0)
            
            # Handle rate limiting safely after response exists
            if response.status_code == 429:
                print("[WARNING] VirusTotal API Rate limit hit. Using safe fallback.", flush=True)
                return {"is_flagged": False, "error": "QuotaExceeded"}

            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious_votes = stats.get("malicious", 0)
                return {"is_flagged": malicious_votes > 0}
            else:
                print(f"VT API Error: {response.status_code} - {response.text}", flush=True)
                return {"is_flagged": False}
                
        except Exception as e:
            print(f"VT Connection Exception: {str(e)}", flush=True)
            return {"is_flagged": False}


async def fetch_abuseipdb(ioc_value: str, ioc_type: str) -> dict:
    """
    Asynchronously queries the AbuseIPDB v2 API.
    Only IP addresses are supported by this specific endpoint.
    """
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
            
            # Handle rate limiting safely after response exists
            if response.status_code == 429:
                print("[WARNING] AbuseIPDB API Rate limit hit. Using safe fallback.", flush=True)
                return {"is_flagged": False, "error": "QuotaExceeded"}

            if response.status_code == 200:
                data = response.json()
                score = data.get("data", {}).get("abuseConfidenceScore", 0)
                return {"is_flagged": score > 50}
            else:
                print(f"AbuseIPDB API Error: {response.status_code}", flush=True)
                return {"is_flagged": False}
                
        except Exception as e:
            print(f"AbuseIPDB Connection Exception: {str(e)}", flush=True)
            return {"is_flagged": False}