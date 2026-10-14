# ThreatMapper

ThreatMapper is a high-performance, multi-tenant Threat Intelligence, IOC Monitoring, and SIEM Orchestration platform built with FastAPI and SQLAlchemy.

## Features

- **Multi-Tenant Architecture**: Strict organizational isolation ensuring organizations can only view and manage their own security assets.
- **JWT Authentication & RBAC**: Secure JSON Web Token authentication with bcrypt password hashing and role-based access control (`analyst`, `admin`, `superadmin`).
- **Real-Time OSINT Threat Intelligence**: Concurrent asynchronous enrichment via VirusTotal v3 and AbuseIPDB v2 with confidence scoring and automated verdicts.
- **Continuous Watchlist Monitoring**: Automated background scheduler scans watchlisted IOCs at configurable intervals.
- **IOC Data Retention**: Daily cleanup purges IOC intelligence records not seen in the past 90 days; watchlists and account data are retained.
- **SIEM Push Integration**: Dispatches threat detections and alerts to connected SIEM solutions (e.g., Splunk HTTP Event Collector).
- **STIX 2.1 Threat Intel Export**: Generates standardized STIX 2.1 JSON indicator bundles for downstream security workflows.
- **Interactive OpenAPI Documentation**: Swagger UI with built-in OAuth2 "Authorize" support.

## Getting Started

### Prerequisites

- Python 3.10+
- PostgreSQL (or local SQLite fallback)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/crypto-socail/Threat-Mapper.git
   cd Threat-Mapper
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Configure environment variables:
   ```bash
   cp .env.example .env
   ```
   Edit `.env` with your configuration:
   ```env
   DATABASE_URL=sqlite:///./threat_mapper.db
   VIRUSTOTAL_API_KEY=your_vt_api_key_here
   ABUSEIPDB_API_KEY=your_abuseipdb_key_here
   JWT_SECRET_KEY=threatmapper_super_secure_jwt_secret_key_2026_at_least_32_bytes
   JWT_ALGORITHM=HS256
   ACCESS_TOKEN_EXPIRE_MINUTES=1440
   ```

### Running the Server

Start the FastAPI application with Uvicorn:
```bash
uvicorn main:app --app-dir backend --host 127.0.0.1 --port 8000 --reload
```

The server will be available at `http://127.0.0.1:8000`.
Explore the interactive API documentation at `http://127.0.0.1:8000/docs`.

### Running Verification Tests

Run the comprehensive verification test suite:
```bash
python test_server_verification.py
```

Run live HTTP end-to-end integration tests:
```bash
python test_live_http.py
```

## API Overview

| Method | Endpoint | Description | Auth Required |
|---|---|---|---|
| `GET` | `/api/health` | Service health status check | No |
| `POST` | `/api/organizations` | Create tenant organization | No |
| `POST` | `/api/auth/register` | Register tenant user and return JWT | No |
| `POST` | `/api/auth/login` | Authenticate with credentials | No |
| `POST` | `/api/auth/token` | OAuth2 form login for Swagger UI | No |
| `GET` | `/api/auth/me` | Fetch active user profile and tenant | Yes (Bearer) |
| `POST` | `/api/lookup` | Query OSINT feeds & score IOC | Yes (Bearer) |
| `POST` | `/api/watchlist` | Add IOC to tenant watchlist | Yes (Bearer) |
| `GET` | `/api/organizations/{org_id}/watchlist` | List tenant watchlist | Yes (Bearer) |
| `POST` | `/api/organizations/{org_id}/siem/config` | Configure tenant SIEM endpoint | Yes (Bearer) |
| `GET` | `/api/organizations/{org_id}/siem/config` | Retrieve tenant SIEM config | Yes (Bearer) |
| `GET` | `/api/export/stix21/{watchlist_id}` | Export threat indicator as STIX 2.1 | Yes (Bearer) |
