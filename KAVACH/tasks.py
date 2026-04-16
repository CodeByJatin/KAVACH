from huey import crontab
from huey_queue import huey
from app import app
from database import db, Asset, Domain
import requests
from datetime import datetime
from scanner.discovery import get_subdomains
from scanner.tls_scanner import scan_subdomain
from scanner.pqc_checker import check_pqc

def emit_event(event, payload):
    try:
        requests.post("http://127.0.0.1:5000/internal/emit", json={"event": event, "payload": payload}, timeout=2)
    except Exception as e:
        print(f"Failed to emit event: {e}")

@huey.task()
def background_discovery_task(user_id, domain_id, domain_name):
    with app.app_context():
        try:
            discovery_result = get_subdomains(domain_name)
            
            # Clear any existing assets for this domain to avoid duplicates
            Asset.query.filter(Asset.domain_id == domain_id, Asset.pqc_score.is_(None)).delete()
            
            # Insert discovered assets (Active, Suspicious)
            for sub in discovery_result.get('active', []):
                new_asset = Asset(domain_id=domain_id, subdomain=sub['subdomain'], ip_address=sub['ip_address'], server_software=sub['server_software'], pqc_status='discovered')
                db.session.add(new_asset)
                
            for sub in discovery_result.get('suspicious', []):
                new_asset = Asset(domain_id=domain_id, subdomain=sub['subdomain'], ip_address=sub['ip_address'], server_software=sub['server_software'], pqc_status='suspicious')
                db.session.add(new_asset)
                
            domain = Domain.query.get(domain_id)
            if domain:
                domain.discovery_status = 'completed'
            db.session.commit()
            print(f"Background discovery completed for {domain_name}")
            emit_event("discovery_complete", {"domain_id": domain_id})
            
            # Phase 3: Auto-Scan mechanism 
            # We can trigger scans automatically if selected
        except Exception as e:
            print(f"Error in background discovery for {domain_name}: {e}")
            domain = Domain.query.get(domain_id)
            if domain:
                domain.discovery_status = 'error'
                db.session.commit()
            emit_event("discovery_error", {"domain_id": domain_id, "error": str(e)})

@huey.task()
def background_scan_task(domain_id, subdomains):
    from app import geolocate_ips
    from scanner.port_scanner import get_open_ports
    with app.app_context():
        domain = Domain.query.get(domain_id)
        if domain:
            domain.status = 'scanning'
            db.session.commit()
        
        total = len(subdomains)
        completed = 0

        for sub in subdomains:
            subdomain = sub.get('subdomain')
            ip_address = sub.get('ip_address')
            server = sub.get('server_software')
            
            scan_data = scan_subdomain(subdomain)
            
            # Run port scanner synchronously during this pass
            open_ports_str = get_open_ports(subdomain)
            
            if not scan_data.get('error'):
                pqc_data = check_pqc(
                    scan_data.get('tls_version'),
                    scan_data.get('cipher_suite'),
                    scan_data.get('key_length'),
                    scan_data.get('key_type'),
                    scan_data.get('signature_oid'),
                    scan_data.get('pubkey_oid')
                )
            else:
                pqc_data = {
                    "pqc_score": 0, "pqc_status": "Failed",
                    "risk_level": "unknown", "color": "", "recommendation": ""
                }
                
            asset_id = sub.get('id')
            if asset_id:
                asset = Asset.query.get(asset_id)
            else:
                asset = Asset.query.filter_by(domain_id=domain_id, subdomain=subdomain).first()
                
            if asset:
                asset.ip_address = ip_address
                asset.open_ports = open_ports_str
                asset.tls_version = scan_data.get('tls_version')
                asset.cipher_suite = scan_data.get('cipher_suite')
                asset.key_length = scan_data.get('key_length')
                asset.key_type = scan_data.get('key_type')
                asset.cert_expiry = scan_data.get('cert_expiry')
                asset.cert_authority = scan_data.get('cert_authority')
                asset.cert_common_name = scan_data.get('cert_common_name')
                asset.cert_fingerprint = scan_data.get('cert_fingerprint')
                asset.server_software = server
                asset.pqc_status = pqc_data.get('pqc_status')
                asset.pqc_score = pqc_data.get('pqc_score')
                asset.risk_level = pqc_data.get('risk_level')
                asset.scan_error = scan_data.get('error')
                asset.scanned_at = datetime.utcnow()
                db.session.commit()
            
            completed += 1
            emit_event("scan_progress", {"domain_id": domain_id, "completed": completed, "total": total})
            
        if domain:
            domain.status = 'completed'
            domain.last_scanned = datetime.utcnow()
            db.session.commit()
            
        geolocate_ips(domain_id)
        emit_event("scan_complete", {"domain_id": domain_id})

@huey.periodic_task(crontab(minute='0', hour='0', day_of_week='0'))
def continuous_watch_task():
    with app.app_context():
        domains = Domain.query.all()
        for domain in domains:
            # Re-run discovery silently without user trigger
            background_discovery_task(domain.user_id, domain.id, domain.domain_name)
            
            # Re-scan suspicious or new assets
            # Fetch updated assets after some time? Since huey runs tasks asynchronously,
            # we should just let discovery finish, but we can't synchronously wait here.
            # So just re-scan all currently known active assets.
            assets = Asset.query.filter_by(domain_id=domain.id).all()
            if assets:
                subdomains = [a.to_dict() for a in assets if a.pqc_status != 'suspicious']
                background_scan_task(domain.id, subdomains)
