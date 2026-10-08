import os
import sys

# Ensure backend directory is in path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))

from fastapi.testclient import TestClient
from main import app
from database import engine, Base, SessionLocal
import models

def run_tests():
    print("=" * 60)
    print("STARTING THREATMAPPER API & JWT VERIFICATION SUITE")
    print("=" * 60)

    # Re-create fresh tables for clean test
    Base.metadata.create_all(bind=engine)
    client = TestClient(app)

    # 1. Health check
    print("\n[1] Testing Health Check (/api/health)...")
    res = client.get("/api/health")
    assert res.status_code == 200, f"Expected 200, got {res.status_code}: {res.text}"
    print(f" -> OK: {res.json()}")

    # 2. Create Organizations
    print("\n[2] Creating Test Organizations...")
    res = client.post("/api/organizations", json={"name": "CyberCorp Security"})
    assert res.status_code == 200, f"Failed to create org: {res.text}"
    org1_id = res.json()["org_id"]
    print(f" -> Org 1 created with ID: {org1_id}")

    res = client.post("/api/organizations", json={"name": "RivalCorp IT"})
    assert res.status_code == 200, f"Failed to create org 2: {res.text}"
    org2_id = res.json()["org_id"]
    print(f" -> Org 2 created with ID: {org2_id}")

    # 3. User Registration (Org 1)
    print("\n[3] Registering User for Org 1...")
    res = client.post("/api/auth/register", json={
        "username": "alice_analyst",
        "password": "SuperSecretPassword123!",
        "org_id": org1_id,
        "email": "alice@cybercorp.com",
        "role": "analyst"
    })
    assert res.status_code == 200, f"Registration failed: {res.text}"
    data = res.json()
    token_org1 = data["access_token"]
    assert token_org1, "Token should be present"
    print(f" -> User registered. Access token received: {token_org1[:25]}...")

    # 4. User Login
    print("\n[4] Testing Login with valid credentials...")
    res = client.post("/api/auth/login", json={
        "username": "alice_analyst",
        "password": "SuperSecretPassword123!"
    })
    assert res.status_code == 200, f"Login failed: {res.text}"
    token_org1 = res.json()["access_token"]
    print(f" -> Login successful!")

    # 5. Invalid credentials check
    print("\n[5] Testing Login with invalid password...")
    res = client.post("/api/auth/login", json={
        "username": "alice_analyst",
        "password": "WrongPassword!"
    })
    assert res.status_code == 401, f"Expected 401, got {res.status_code}"
    print(" -> Correctly rejected invalid credentials with 401 Unauthorized.")

    # 6. Auth Profile Check (/api/auth/me)
    print("\n[6] Testing /api/auth/me endpoint...")
    headers_org1 = {"Authorization": f"Bearer {token_org1}"}
    res = client.get("/api/auth/me", headers=headers_org1)
    assert res.status_code == 200, f"Profile check failed: {res.text}"
    profile = res.json()
    assert profile["username"] == "alice_analyst"
    assert profile["org_id"] == org1_id
    print(f" -> Current user profile: {profile['username']} (Org: {profile['org_name']} [ID {profile['org_id']}])")

    # 7. Unauthenticated request rejection
    print("\n[7] Testing access rejection without JWT token...")
    res = client.get(f"/api/organizations/{org1_id}/watchlist")
    assert res.status_code == 401, f"Expected 401, got {res.status_code}"
    print(" -> Correctly blocked unauthenticated request with 401.")

    # 8. Add to Watchlist (Org 1)
    print("\n[8] Adding IOC to Org 1 Watchlist...")
    res = client.post("/api/watchlist", json={
        "org_id": org1_id,
        "ioc_value": "185.220.101.5",
        "ioc_type": "ip"
    }, headers=headers_org1)
    assert res.status_code == 200, f"Watchlist addition failed: {res.text}"
    watchlist_id = res.json().get("watchlist_id")
    print(f" -> Added IOC to Watchlist: {res.json()['message']} (ID: {watchlist_id})")

    # 9. Get Watchlist (Org 1)
    print("\n[9] Fetching Watchlist for Org 1...")
    res = client.get(f"/api/organizations/{org1_id}/watchlist", headers=headers_org1)
    assert res.status_code == 200, f"Fetch watchlist failed: {res.text}"
    items = res.json()["watchlist"]
    assert len(items) >= 1
    print(f" -> Successfully retrieved {len(items)} watchlist item(s).")

    # 10. Multi-Tenant Isolation Check (Cross-Org Prevention)
    print("\n[10] Testing Multi-Tenant Isolation (Org 2 User trying to access Org 1 data)...")
    # Register user in Org 2
    res = client.post("/api/auth/register", json={
        "username": "bob_competitor",
        "password": "Password456!",
        "org_id": org2_id,
        "email": "bob@rivalcorp.com",
        "role": "analyst"
    })
    assert res.status_code == 200
    token_org2 = res.json()["access_token"]
    headers_org2 = {"Authorization": f"Bearer {token_org2}"}

    # Bob tries to view Alice's Org 1 watchlist
    res = client.get(f"/api/organizations/{org1_id}/watchlist", headers=headers_org2)
    assert res.status_code == 403, f"Expected 403 Forbidden, got {res.status_code}: {res.text}"
    print(f" -> Blocked cross-tenant access! Response: {res.status_code} {res.json()['detail']}")

    # Bob tries to add IOC to Alice's Org 1 watchlist
    res = client.post("/api/watchlist", json={
        "org_id": org1_id,
        "ioc_value": "1.1.1.1",
        "ioc_type": "ip"
    }, headers=headers_org2)
    assert res.status_code == 403, f"Expected 403 Forbidden, got {res.status_code}: {res.text}"
    print(f" -> Blocked cross-tenant write! Response: {res.status_code} {res.json()['detail']}")

    # 11. SIEM Configuration & Cross-Tenant Protection
    print("\n[11] Testing SIEM Configuration & Tenant Scoping...")
    res = client.post(f"/api/organizations/{org1_id}/siem/config", json={
        "siem_type": "splunk",
        "endpoint_url": "https://splunk.cybercorp.com:8088/services/collector/raw",
        "auth_token": "cybercorp-secret-token-12345",
        "sync_mode": "push"
    }, headers=headers_org1)
    assert res.status_code == 200, f"Failed SIEM config: {res.text}"
    print(f" -> Configured SIEM for Org 1: {res.json()['message']}")

    # Verify Bob cannot view Org 1's SIEM configs
    res = client.get(f"/api/organizations/{org1_id}/siem/config", headers=headers_org2)
    assert res.status_code == 403
    print(" -> Blocked Bob from viewing Org 1's SIEM token! (403 Forbidden)")

    # Alice can view Org 1's SIEM configs
    res = client.get(f"/api/organizations/{org1_id}/siem/config", headers=headers_org1)
    assert res.status_code == 200
    assert len(res.json()["configs"]) == 1
    print(f" -> Alice successfully retrieved Org 1 SIEM config: {res.json()['configs'][0]['siem_type']}")

    # 12. STIX 2.1 Export
    if watchlist_id:
        print(f"\n[12] Testing STIX 2.1 Bundle Export for watchlist item {watchlist_id}...")
        res = client.get(f"/api/export/stix21/{watchlist_id}", headers=headers_org1)
        assert res.status_code == 200, f"STIX export failed: {res.text}"
        stix = res.json()
        assert stix["type"] == "bundle"
        assert len(stix["objects"]) == 1
        assert stix["objects"][0]["type"] == "indicator"
        print(f" -> STIX 2.1 indicator generated: {stix['objects'][0]['name']}")

        # Bob cannot export Alice's watchlist
        res = client.get(f"/api/export/stix21/{watchlist_id}", headers=headers_org2)
        assert res.status_code == 403
        print(" -> Blocked Bob from exporting Org 1 STIX bundle! (403 Forbidden)")

    print("\n" + "=" * 60)
    print("ALL API & JWT AUTHENTICATION TESTS PASSED PERFECTLY!")
    print("=" * 60)

if __name__ == "__main__":
    run_tests()
