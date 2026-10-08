import re
from typing import Dict, Any

# --- 1. Input Normalization & Validation [NEW in v2] ---

def validate_and_normalize_ioc(ioc_value: str, ioc_type: str) -> str:
    """
    Sanitizes the input and validates it against expected patterns before 
    burning external API quotas. Malformed inputs should trigger a 400 error.
    """
    # Normalize: lowercase and strip trailing slashes
    clean_ioc = ioc_value.lower().strip().rstrip('/')
    
    if ioc_type == "ip":
        # Basic IPv4 validation pattern
        pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
        if not pattern.match(clean_ioc):
            raise ValueError(f"Invalid IPv4 format: {clean_ioc}")
            
    elif ioc_type == "hash":
        # Validates 32-hex (MD5) or 64-hex (SHA256) lengths
        if len(clean_ioc) not in (32, 64) or not re.fullmatch(r"[a-f0-9]+", clean_ioc):
            raise ValueError(f"Invalid MD5 or SHA256 hash: {clean_ioc}")
            
    # Domain/URL validation could be added here
    
    return clean_ioc


# --- 2. Canonical Confidence Scoring ---

def calculate_confidence_score(source_results: Dict[str, Any]) -> tuple[float, str]:
    """
    Computes a composite score across all queried sources and determines the final verdict.
    """
    # Example weights mapping high-fidelity engines like VirusTotal heavier
    weights = {
        "virustotal": 10.0,
        "abuseipdb": 7.0,
        "urlhaus": 8.0,
        "misp": 9.0
    }
    
    total_queried_weight = 0.0
    total_flagged_weight = 0.0
    
    for source, data in source_results.items():
        if source in weights:
            total_queried_weight += weights[source]
            # Assuming 'is_flagged' is a boolean extracted from the raw API payload
            if data.get("is_flagged"):
                total_flagged_weight += weights[source]
                
    if total_queried_weight == 0:
        return 0.0, "not currently known as bad"
        
    # v2 Formula: (Sum of Flagged Weights / Sum of All Queried Weights) * 100
    confidence_score = (total_flagged_weight / total_queried_weight) * 100
    
    # Verdict Thresholds
    if confidence_score > 60:
        verdict = "malicious"
    elif 21 <= confidence_score <= 60:
        verdict = "suspicious"
    else:
        verdict = "not currently known as bad" # Never guaranteed as safe
        
    return round(confidence_score, 2), verdict