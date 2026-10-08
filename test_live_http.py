import httpx

BASE_URL = "http://127.0.0.1:8000"

def test_live_server():
    print("Testing live FastAPI server at", BASE_URL)
    with httpx.Client(base_url=BASE_URL, timeout=10.0) as client:
        # 1. Health
        r = client.get("/api/health")
        assert r.status_code == 200, f"Health check failed: {r.text}"
        print("[+] GET /api/health:", r.json())

        # 2. OpenAPI JSON
        r = client.get("/openapi.json")
        assert r.status_code == 200, f"OpenAPI schema failed: {r.status_code}"
        print("[+] GET /openapi.json: loaded schema, version:", r.json().get("info", {}).get("version"))

        # 3. Create Org
        r = client.post("/api/organizations", json={"name": "LiveTest Sentinel Org"})
        assert r.status_code == 200, f"Org creation failed: {r.text}"
        org_data = r.json()
        org_id = org_data["org_id"]
        print(f"[+] POST /api/organizations: Org created with ID {org_id}")

        # 4. Register User
        r = client.post("/api/auth/register", json={
            "username": f"analyst_org_{org_id}",
            "password": "StrongPassword123!",
            "org_id": org_id,
            "email": f"analyst{org_id}@sentinel.org",
            "role": "analyst"
        })
        assert r.status_code == 200, f"Register failed: {r.text}"
        auth_data = r.json()
        token = auth_data["access_token"]
        print(f"[+] POST /api/auth/register: User registered. Token: {token[:20]}...")

        # 5. User Login
        r = client.post("/api/auth/login", json={
            "username": f"analyst_org_{org_id}",
            "password": "StrongPassword123!"
        })
        assert r.status_code == 200, f"Login failed: {r.text}"
        token = r.json()["access_token"]
        print("[+] POST /api/auth/login: Logged in successfully!")

        headers = {"Authorization": f"Bearer {token}"}

        # 6. Auth Me
        r = client.get("/api/auth/me", headers=headers)
        assert r.status_code == 200, f"Auth me failed: {r.text}"
        profile = r.json()
        print(f"[+] GET /api/auth/me: Hello {profile['username']} from {profile['org_name']} (Role: {profile['role']})")

        # 7. Add to watchlist
        r = client.post("/api/watchlist", json={
            "org_id": org_id,
            "ioc_value": "198.51.100.24",
            "ioc_type": "ip"
        }, headers=headers)
        assert r.status_code == 200, f"Watchlist add failed: {r.text}"
        w_id = r.json().get("watchlist_id")
        print(f"[+] POST /api/watchlist: {r.json()['message']} (Watchlist ID: {w_id})")

        # 8. Query watchlist
        r = client.get(f"/api/organizations/{org_id}/watchlist", headers=headers)
        assert r.status_code == 200, f"Get watchlist failed: {r.text}"
        items = r.json()["watchlist"]
        print(f"[+] GET /api/organizations/{org_id}/watchlist: {len(items)} item(s) retrieved")

        # 9. STIX 2.1 Export
        if w_id:
            r = client.get(f"/api/export/stix21/{w_id}", headers=headers)
            assert r.status_code == 200, f"STIX export failed: {r.text}"
            print(f"[+] GET /api/export/stix21/{w_id}: STIX 2.1 bundle generated successfully!")

        print("\nALL LIVE SERVER & JWT CHECKS PASSED OVER HTTP!")

if __name__ == "__main__":
    test_live_server()
