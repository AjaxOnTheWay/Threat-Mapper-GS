import httpx
from datetime import datetime

async def push_to_splunk(endpoint_url: str, auth_token: str, ioc_data: dict):
    """Pushes a high-confidence threat alert to Splunk's HTTP Event Collector (HEC)."""
    headers = {
        "Authorization": f"Splunk {auth_token}",
        "Content-Type": "application/json"
    }
    
    # Splunk HEC strictly requires the payload to be wrapped in an "event" key
    payload = {
        "time": datetime.utcnow().timestamp(),
        "sourcetype": "threatmapper:alert",
        "event": ioc_data
    }
    
    try:
        # We use a 5-second timeout so a slow SIEM doesn't freeze our background loop
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(endpoint_url, json=payload, headers=headers)
            response.raise_for_status()
            return True
    except Exception as e:
        print(f"        -> ❌ Splunk Push Failed: {e}", flush=True)
        return False