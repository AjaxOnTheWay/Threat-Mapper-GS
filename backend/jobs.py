from apscheduler.schedulers.asyncio import AsyncIOScheduler
from datetime import datetime
import asyncio
from database import SessionLocal
import models
from connectors import fetch_virustotal, fetch_abuseipdb
from engine import calculate_confidence_score
from siem import push_to_splunk

scheduler = AsyncIOScheduler()

async def scan_watchlist():
    print(f"\n[{datetime.utcnow()}] INTERVAL JOB: Scanning database watchlist...", flush=True)
    
    # 1. Fetch data synchronously but quickly
    try:
        db = SessionLocal()
        watchlist = db.query(models.WatchlistRecord).all()
        
        records_to_scan = [
            {
                "id": r.id, 
                "ioc_value": r.ioc_value, 
                "ioc_type": r.ioc_type, 
                "org_id": r.org_id
            } for r in watchlist
        ]
    except Exception as e:
        print(f" -> [ERROR] DB ERROR: {e}", flush=True)
        return
    finally:
        db.close()

    if not records_to_scan:
        print(" -> Watchlist is currently empty.", flush=True)
        return

    print(f" -> Found {len(records_to_scan)} IOC(s). Commencing re-scan...", flush=True)
    
    # 2. Asynchronously scan each record
    for record in records_to_scan:
        print(f"    [*] Checking {record['ioc_type']}: {record['ioc_value']} (Org: {record['org_id']})", flush=True)
        
        vt_task = fetch_virustotal(record['ioc_value'], record['ioc_type'])
        abuse_task = fetch_abuseipdb(record['ioc_value'], record['ioc_type'])
        
        vt_result, abuse_result = await asyncio.gather(vt_task, abuse_task)
        
        live_source_results = {
            "virustotal": vt_result,
            "abuseipdb": abuse_result
        }
        
        score, verdict = calculate_confidence_score(live_source_results)
        print(f"        -> VirusTotal Flagged: {vt_result.get('is_flagged', False)}", flush=True)
        print(f"        -> AbuseIPDB Flagged: {abuse_result.get('is_flagged', False)}", flush=True)
        print(f"        -> Final Engine Verdict: {verdict.upper()} (Score: {score})", flush=True)
        
        # 3. Update the database with the new scan time
        # 3. Update the database and Alert the SIEM
        try:
            update_db = SessionLocal()
            
            # A. Update the timestamp
            db_record = update_db.query(models.WatchlistRecord).filter(models.WatchlistRecord.id == record['id']).first()
            if db_record:
                db_record.last_checked = datetime.utcnow()
                update_db.commit()
                
            # B. If the threat is bad, find the Org's SIEM config and fire the alert
            if score >= 50:  # Threshold for a malicious alert
                print(f"        -> [ALERT] THREAT DETECTED! Locating SIEM config for Org {record['org_id']}...", flush=True)
                
                # Look up the specific SIEM configuration for this tenant
                siem_config = update_db.query(models.SiemConfigRecord).filter(
                    models.SiemConfigRecord.org_id == record['org_id'],
                    models.SiemConfigRecord.siem_type == 'splunk'
                ).first()
                
                if siem_config and siem_config.endpoint_url:
                    alert_data = {
                        "ioc_value": record['ioc_value'],
                        "ioc_type": record['ioc_type'],
                        "verdict": verdict,
                        "confidence_score": score
                    }
                    
                    # Fire the alert to Splunk using the tenant's saved token!
                    success = await push_to_splunk(
                        endpoint_url=siem_config.endpoint_url,
                        auth_token=siem_config.auth_token,
                        ioc_data=alert_data
                    )
                    if success:
                        print(f"        -> [SUCCESS] Alert successfully pushed to Splunk for Org {record['org_id']}", flush=True)
                else:
                    print(f"        -> [WARNING] No active Splunk configuration found for Org {record['org_id']}. Alert dropped.", flush=True)

        except Exception as e:
            print(f"        -> [ERROR] DB/Alert Error: {e}", flush=True)
        finally:
            update_db.close()

def run_retention_cleanup():
    print(f"[{datetime.now()}] [CLEANUP] CRON JOB: Sweeping database for records older than 90 days...", flush=True)

def start_scheduler():
    scheduler.add_job(scan_watchlist, 'interval', minutes=3)
    scheduler.add_job(run_retention_cleanup, 'cron', hour=0, minute=0)
    scheduler.start()
    print("[SCHEDULER] Background scheduler initialized and running.", flush=True)