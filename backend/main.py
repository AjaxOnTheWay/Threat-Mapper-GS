from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from pydantic import BaseModel, HttpUrl
from typing import Optional, List
import asyncio
from datetime import datetime
from contextlib import asynccontextmanager
from uuid import uuid4

from database import engine, get_db
import models
from jobs import start_scheduler
from engine import validate_and_normalize_ioc, calculate_confidence_score
from connectors import (
    fetch_virustotal, 
    fetch_abuseipdb, 
    fetch_urlhaus, 
    fetch_misp, 
    fetch_hibp
)
from auth import (
    hash_password,
    verify_password,
    create_access_token,
    get_current_user,
    verify_tenant_access,
)

# Build all tables in the database
models.Base.metadata.create_all(bind=engine)

@asynccontextmanager
async def lifespan(app: FastAPI):
    start_scheduler()
    yield
    print("Shutting down background jobs...")

app = FastAPI(
    title="ThreatMapper v2 API",
    description="Multi-tenant Threat Intelligence & Monitoring Platform with JWT Authentication",
    version="2.0.0",
    lifespan=lifespan
)

# --- Pydantic Data Models ---
class UserRegister(BaseModel):
    username: str
    password: str
    org_id: int
    email: Optional[str] = None
    role: Optional[str] = "analyst"

class UserLogin(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    org_id: int
    role: str

class WatchlistCreate(BaseModel):
    org_id: int
    ioc_value: str
    ioc_type: str

class IOCRequest(BaseModel):
    ioc_value: str
    ioc_type: str

class OrganizationCreate(BaseModel):
    name: str

class SiemConfigCreate(BaseModel):
    siem_type: str
    endpoint_url: Optional[HttpUrl] = None
    auth_token: str
    sync_mode: str = "push"

# --- Health Check ---
@app.get("/api/health")
async def health_check():
    """Simple health check endpoint for monitoring."""
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}

# --- Authentication Endpoints ---
@app.post("/api/auth/register", response_model=TokenResponse)
async def register_user(req: UserRegister, db: Session = Depends(get_db)):
    """Registers a new user within a tenant organization and returns a signed JWT."""
    # Check if organization exists
    org = db.query(models.Organization).filter(models.Organization.id == req.org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    # Check for duplicate username
    existing_user = db.query(models.User).filter(models.User.username == req.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")

    # Check for duplicate email if provided
    if req.email:
        existing_email = db.query(models.User).filter(models.User.email == req.email).first()
        if existing_email:
            raise HTTPException(status_code=400, detail="Email already registered")

    hashed_pw = hash_password(req.password)
    new_user = models.User(
        username=req.username,
        email=req.email,
        hashed_password=hashed_pw,
        org_id=req.org_id,
        role=req.role or "analyst"
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    token = create_access_token(data={
        "sub": new_user.username,
        "org_id": new_user.org_id,
        "role": new_user.role
    })
    return {
        "access_token": token,
        "token_type": "bearer",
        "username": new_user.username,
        "org_id": new_user.org_id,
        "role": new_user.role
    }

@app.post("/api/auth/login", response_model=TokenResponse)
async def login_json(credentials: UserLogin, db: Session = Depends(get_db)):
    """Authenticates a user via JSON payload and returns a signed JWT."""
    user = db.query(models.User).filter(models.User.username == credentials.username).first()
    if not user or not verify_password(credentials.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled"
        )

    token = create_access_token(data={
        "sub": user.username,
        "org_id": user.org_id,
        "role": user.role
    })
    return {
        "access_token": token,
        "token_type": "bearer",
        "username": user.username,
        "org_id": user.org_id,
        "role": user.role
    }

@app.post("/api/auth/token")
async def login_oauth2(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """OAuth2 password form login endpoint for OpenAPI / Swagger UI Authorize support."""
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled"
        )

    token = create_access_token(data={
        "sub": user.username,
        "org_id": user.org_id,
        "role": user.role
    })
    return {"access_token": token, "token_type": "bearer"}

@app.get("/api/auth/me")
async def get_current_user_profile(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieves identity and organization details for the active authenticated user."""
    org = db.query(models.Organization).filter(models.Organization.id == current_user.org_id).first()
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "role": current_user.role,
        "org_id": current_user.org_id,
        "org_name": org.name if org else None,
        "created_at": current_user.created_at
    }

# --- Core IOC Lookup Endpoint ---
@app.post("/api/lookup")
async def lookup_ioc(
    request: IOCRequest, 
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """Queries OSINT feeds and updates or records threat scoring."""
    try:
        clean_ioc = validate_and_normalize_ioc(request.ioc_value, request.ioc_type)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
   # Query live sources concurrently
    vt_task = fetch_virustotal(clean_ioc, request.ioc_type)
    abuseipdb_task = fetch_abuseipdb(clean_ioc, request.ioc_type)
    urlhaus_task = fetch_urlhaus(clean_ioc, request.ioc_type)
    misp_task = fetch_misp(clean_ioc, request.ioc_type)
    hibp_task = fetch_hibp(clean_ioc, request.ioc_type)

    vt_result, abuse_result, urlhaus_result, misp_result, hibp_result = await asyncio.gather(
        vt_task, abuseipdb_task, urlhaus_task, misp_task, hibp_task
    )
    
    live_source_results = {
        "virustotal": vt_result,
        "abuseipdb": abuse_result,
        "urlhaus": urlhaus_result,
        "misp": misp_result,
        "hibp": hibp_result
    }
    
    score, verdict = calculate_confidence_score(live_source_results)
    
    # Database persistence
    existing_record = db.query(models.IOCRecord).filter(models.IOCRecord.ioc_value == clean_ioc).first()
    if existing_record:
        existing_record.confidence_score = score
        existing_record.verdict = verdict
        existing_record.last_seen = datetime.utcnow()
    else:
        new_record = models.IOCRecord(
            ioc_value=clean_ioc,
            ioc_type=request.ioc_type,
            verdict=verdict,
            confidence_score=score
        )
        db.add(new_record)
        
    db.commit()

    return {
        "ioc": clean_ioc,
        "type": request.ioc_type,
        "verdict": verdict, 
        "confidence_score": score,
        "sources_queried": list(live_source_results.keys())
    }

# --- Watchlist Endpoints ---
@app.post("/api/watchlist")
async def add_to_watchlist(
    request: WatchlistCreate, 
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """Adds a new IOC to an organization's continuous monitoring watchlist (multi-tenant protected)."""
    verify_tenant_access(current_user, request.org_id)

    org = db.query(models.Organization).filter(models.Organization.id == request.org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    existing = db.query(models.WatchlistRecord).filter(
        models.WatchlistRecord.org_id == request.org_id,
        models.WatchlistRecord.ioc_value == request.ioc_value
    ).first()
    
    if existing:
        return {"status": "info", "message": "IOC is already on the watchlist"}

    new_watch = models.WatchlistRecord(
        org_id=request.org_id,
        ioc_value=request.ioc_value,
        ioc_type=request.ioc_type
    )
    db.add(new_watch)
    db.commit()
    db.refresh(new_watch)
    
    return {
        "status": "success", 
        "watchlist_id": new_watch.id,
        "message": f"{request.ioc_value} added to watchlist for org {request.org_id}"
    }

@app.get("/api/organizations/{org_id}/watchlist")
async def get_watchlist(
    org_id: int, 
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """Retrieves all actively watched IOCs for a specific organization (multi-tenant protected)."""
    verify_tenant_access(current_user, org_id)

    watchlist = db.query(models.WatchlistRecord).filter(models.WatchlistRecord.org_id == org_id).all()
    
    return {
        "org_id": org_id,
        "watchlist": [
            {
                "id": w.id,
                "ioc_value": w.ioc_value,
                "ioc_type": w.ioc_type,
                "added_at": w.added_at,
                "last_checked": w.last_checked
            } for w in watchlist
        ]
    }

# --- Multi-Tenant SIEM Endpoints ---
@app.post("/api/organizations")
async def create_organization(org: OrganizationCreate, db: Session = Depends(get_db)):
    """Creates a new tenant organization."""
    new_org = models.Organization(name=org.name)
    db.add(new_org)
    db.commit()
    db.refresh(new_org)
    return {"message": "Organization created", "org_id": new_org.id, "name": new_org.name}

@app.post("/api/organizations/{org_id}/siem/config")
async def update_siem_config(
    org_id: int, 
    config: SiemConfigCreate, 
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """Creates or updates a SIEM configuration exclusively for the specified org_id."""
    verify_tenant_access(current_user, org_id)

    org = db.query(models.Organization).filter(models.Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    existing_config = db.query(models.SiemConfigRecord).filter(
        models.SiemConfigRecord.org_id == org_id,
        models.SiemConfigRecord.siem_type == config.siem_type
    ).first()

    if existing_config:
        existing_config.endpoint_url = str(config.endpoint_url) if config.endpoint_url else None
        existing_config.auth_token = config.auth_token
        existing_config.sync_mode = config.sync_mode
        existing_config.updated_at = datetime.utcnow()
        message = "Configuration updated"
    else:
        new_config = models.SiemConfigRecord(
            org_id=org_id,
            siem_type=config.siem_type,
            endpoint_url=str(config.endpoint_url) if config.endpoint_url else None,
            auth_token=config.auth_token,
            sync_mode=config.sync_mode
        )
        db.add(new_config)
        message = "Configuration created"

    db.commit()
    return {"status": "success", "message": f"{config.siem_type} {message} for org {org_id}"}

@app.get("/api/organizations/{org_id}/siem/config")
async def get_siem_configs(
    org_id: int, 
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """Retrieves all SIEM configurations securely scoped to the requested org_id."""
    verify_tenant_access(current_user, org_id)

    configs = db.query(models.SiemConfigRecord).filter(models.SiemConfigRecord.org_id == org_id).all()
    if not configs:
        return {"org_id": org_id, "configs": []}
    
    return {
        "org_id": org_id,
        "configs": [
            {   
                "siem_type": c.siem_type,
                "endpoint_url": c.endpoint_url,
                "sync_mode": c.sync_mode,
                "updated_at": c.updated_at
            } for c in configs
        ]
    }

# --- STIX 2.1 Endpoint ---
@app.get("/api/export/stix21/{watchlist_id}")
def export_stix21(
    watchlist_id: int, 
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """Exports a specific watchlisted threat as a STIX 2.1 JSON Bundle."""
    record = db.query(models.WatchlistRecord).filter(models.WatchlistRecord.id == watchlist_id).first()
    
    if not record:
        raise HTTPException(status_code=404, detail="Watchlist record not found")
    
    verify_tenant_access(current_user, record.org_id)
    
    indicator_id = f"indicator--{uuid4()}"
    bundle_id = f"bundle--{uuid4()}"
    now_iso = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    
    ioc_type_clean = record.ioc_type.lower()
    
    pattern_map = {
        "ip": f"[ipv4-addr:value = '{record.ioc_value}']",
        "domain": f"[domain-name:value = '{record.ioc_value}']",
        "hash": f"[file:hashes.SHA-256 = '{record.ioc_value}']",
        "siem": f"[ipv4-addr:value = '{record.ioc_value}']"
    }
    pattern = pattern_map.get(ioc_type_clean, f"[custom-type:value = '{record.ioc_value}']")

    stix_bundle = {
        "type": "bundle",
        "id": bundle_id,
        "objects": [
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created": now_iso,
                "modified": now_iso,
                "name": f"ThreatMapper Alert - {record.ioc_value}",
                "description": f"Automated STIX 2.1 export for organization {record.org_id}",
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": now_iso
            }
        ]
    }
    return stix_bundle