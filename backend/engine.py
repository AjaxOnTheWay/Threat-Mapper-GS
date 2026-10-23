import re
from typing import Dict, Any

# --- 1. Input Normalization & Validation [NEW in v2] ---

def validate_and_normalize_ioc(ioc_value: str, ioc_type: str) -> str:
    """
    Sanitizes the input and validates it against expected patterns before 
    burning external API quotas. Malformed inputs should trigger a 400 error.
    """
    # Normalize: lowercase and strip trailing slashes
    clean_ioc = ioc_value.strip().lower()
    
    if ioc_type == "ip":
        if not re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", clean_ioc):
            raise ValueError(f"Invalid IPv4 format: {clean_ioc}")
            
    elif ioc_type == "hash":
        if not re.match(r"^([a-f0-9]{32}|[a-f0-9]{64})$", clean_ioc):
            raise ValueError(f"Invalid MD5 or SHA256 format: {clean_ioc}")
            
    elif ioc_type == "domain":
        # Matches standard RFC 1035 domains (e.g., evil-site.com)
        if not re.match(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$", clean_ioc):
            raise ValueError(f"Invalid Domain format: {clean_ioc}")
            
    elif ioc_type == "url":
        # Ensures URLs are properly structured
        if not re.match(r"^https?://[\w\-]+(\.[\w\-]+)+[/#?]?.*$", clean_ioc):
            raise ValueError(f"Invalid URL format: {clean_ioc}")
            
    return clean_ioc


# --- 2. Canonical Confidence Scoring ---

def calculate_confidence_score(source_results: Dict[str, Any]) -> tuple[float, str]:
    """Computes a composite score across all queried sources and determines the final verdict."""
    weights = {
        "virustotal": 10.0,
        "abuseipdb": 7.0,
        "urlhaus": 8.0,
        "misp": 9.0,
        "hibp": 6.0  # <-- Added HIBP weight for email breaches
    }
    
    total_queried_weight = 0.0
    total_flagged_weight = 0.0
    
    for source, data in source_results.items():
        if source in weights:
            total_queried_weight += weights[source]
            if data.get("is_flagged"):
                total_flagged_weight += weights[source]
                
    if total_queried_weight == 0:
        return 0.0, "not currently known as bad"
        
    confidence_score = (total_flagged_weight / total_queried_weight) * 100
    
    if confidence_score > 60:
        verdict = "malicious"
    elif 21 <= confidence_score <= 60:
        verdict = "suspicious"
    else:
        verdict = "not currently known as bad"
        
    return round(confidence_score, 2), verdict