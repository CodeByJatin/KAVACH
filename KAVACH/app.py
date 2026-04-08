import os
if os.environ.get('KAVACH_NO_PATCH') != '1':
    import eventlet
    eventlet.monkey_patch()


import json
import requests
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, send_file
from werkzeug.security import generate_password_hash, check_password_hash
import threading
import io
import time
from datetime import datetime
from functools import wraps
import geoip2.database
import geoip2.errors
import pyotp
import qrcode
import base64
import csv
from sqlalchemy.exc import IntegrityError
from flask_socketio import SocketIO

from database import db, User, Domain, Asset, IPRecord
from scanner.discovery import get_subdomains
from scanner.tls_scanner import scan_subdomain
from scanner.pqc_checker import check_pqc
from scanner.cbom_builder import build_cbom_data

# ReportLab imports
from reportlab.lib.pagesizes import letter, landscape
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

app = Flask(__name__)
# In production, use a secure secret key via env var
app.secret_key = 'kavach_super_secret_key_dev'

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(os.path.dirname(__file__), 'kavach.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
socketio = SocketIO(app, cors_allowed_origins="*")

with app.app_context():
    db.create_all()

# ---------------------------------------------------------------------------
# DECORATORS
# ---------------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ---------------------------------------------------------------------------
# TEMPLATE ROUTES
# ---------------------------------------------------------------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            # If user has MFA enabled, redirect to OTP verification
            if user.mfa_enabled:
                session['mfa_user_id'] = user.id
                session['mfa_user_name'] = user.name
                return redirect(url_for('verify_otp'))
            else:
                # No MFA configured yet, log in directly
                session['user_id'] = user.id
                session['user_name'] = user.name
                return redirect(url_for('index'))
            
        return render_template('login.html', error='Invalid email or password')
        
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        
        hashed_pw = generate_password_hash(password)
        totp_secret = pyotp.random_base32()
        
        try:
            new_user = User(name=name, email=email, password=hashed_pw, totp_secret=totp_secret)
            db.session.add(new_user)
            db.session.commit()
            
            session['user_id'] = new_user.id
            session['user_name'] = new_user.name
            # Redirect to MFA setup page to show QR code
            return redirect(url_for('setup_mfa'))
            
        except IntegrityError:
            db.session.rollback()
            return render_template('register.html', error='Email already exists')
            
    return render_template('register.html')

@app.route('/setup-mfa', methods=['GET', 'POST'])
@login_required
def setup_mfa():
    from_dashboard = request.args.get('from') == 'dashboard'
    
    user = User.query.get(session['user_id'])
    
    totp_secret = user.totp_secret
    
    # Generate secret if user doesn't have one yet (legacy users)
    if not totp_secret:
        totp_secret = pyotp.random_base32()
        user.totp_secret = totp_secret
        db.session.commit()
    
    if request.method == 'POST':
        otp_code = request.form.get('otp', '').strip()
        from_dash_post = request.form.get('from_dashboard') == '1'
        totp = pyotp.TOTP(totp_secret)
        if totp.verify(otp_code, valid_window=1):
            # Code is correct — enable MFA
            user.mfa_enabled = 1
            db.session.commit()
            return redirect(url_for('index'))
        else:
            # Generate QR again and show error
            totp = pyotp.TOTP(totp_secret)
            provisioning_uri = totp.provisioning_uri(name=user.email, issuer_name='KAVACH Platform')
            qr = qrcode.make(provisioning_uri)
            buf = io.BytesIO()
            qr.save(buf, format='PNG')
            buf.seek(0)
            qr_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')
            return render_template('setup_mfa.html', qr_code=qr_b64, secret=totp_secret, 
                                   error='Invalid code. Please try again.',
                                   from_dashboard=from_dash_post)
    
    # Generate QR code as base64 image
    totp = pyotp.TOTP(totp_secret)
    provisioning_uri = totp.provisioning_uri(
        name=user.email,
        issuer_name='KAVACH Platform'
    )
    
    qr = qrcode.make(provisioning_uri)
    buf = io.BytesIO()
    qr.save(buf, format='PNG')
    buf.seek(0)
    qr_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')
    
    return render_template('setup_mfa.html', qr_code=qr_b64, secret=totp_secret, from_dashboard=from_dashboard)

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    # Must have passed password check first
    if 'mfa_user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        otp_code = request.form.get('otp', '').strip()
        
        user = User.query.get(session['mfa_user_id'])
        
        if user and user.totp_secret:
            totp = pyotp.TOTP(user.totp_secret)
            if totp.verify(otp_code, valid_window=1):
                # OTP valid — complete login
                session['user_id'] = user.id
                session['user_name'] = user.name
                session.pop('mfa_user_id', None)
                session.pop('mfa_user_name', None)
                return redirect(url_for('index'))
        
        return render_template('verify_otp.html', error='Invalid or expired code. Please try again.')
    
    return render_template('verify_otp.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@app.route('/index')
@login_required
def index():
    return render_template('index.html')

@app.route('/pages/<page>')
@login_required
def render_page(page):
    # Helper route to load partials via JS
    return render_template(f'pages/{page}.html')

@app.route('/me')
@login_required
def me():
    return jsonify({"user_id": session['user_id'], "name": session.get('user_name', 'User')})

@app.route('/api/mfa-status')
@login_required
def api_mfa_status():
    user = User.query.get(session['user_id'])
    return jsonify({"mfa_enabled": bool(user.mfa_enabled) if user else False})

# ---------------------------------------------------------------------------
# AI CHAT & RAG ENGINE
# ---------------------------------------------------------------------------

def get_rag_context(user_id, asset_id=None):
    """Assembles security context from files and database."""
    context = ""
    
    # 1. Load Standards & Glossary
    kb_path = os.path.join(app.root_path, 'knowledge')
    if os.path.exists(kb_path):
        for filename in ['nist_pqc.txt', 'kavach_glossary.txt', 'remediation_snippets.txt']:
            file_path = os.path.join(kb_path, filename)
            if os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8') as f:
                    context += f"\n--- {filename} ---\n{f.read()}\n"
                    
    # 2. Load User's Vulnerable Assets
    if asset_id:
        asset = Asset.query.get(asset_id)
        if asset and asset.domain.user_id == user_id:
            context += f"\n--- TARGET VULNERABLE ASSET ({asset.subdomain}) ---\n"
            context += f"Details: Score={asset.pqc_score}, TLS={asset.tls_version}, Server={asset.server_software}, Cipher={asset.cipher_suite}, Key Length={asset.key_length}, Risk Level={asset.risk_level}\n"
            context += "INSTRUCTION: The user is asking for an actionable remediation patch specifically for this asset. Provide exact configuration snippets (e.g. Nginx config, Apache config) to upgrade TLS to 1.3 and implement ML-KEM/Kyber hybrid ciphers where applicable. Refer to remediation_snippets.txt if available.\n"
    else:
        assets = Asset.query.join(Domain).filter(Domain.user_id == user_id, Asset.risk_level.isnot(None)).limit(10).all()
        
        if assets:
            context += "\n--- USER DISCOVERED ASSETS ---\n"
            for a in assets:
                context += f"- {a.subdomain}: Score={a.pqc_score}, Risk={a.risk_level}, TLS={a.tls_version}\n"
            
    return context

@app.route('/api/chat', methods=['POST'])
@login_required
def api_chat():
    data = request.json
    user_message = data.get('message', '')
    asset_id = data.get('asset_id')
    
    # Check if Ollama is running
    ollama_url = "http://127.0.0.1:11434/api/chat"
    try:
        # Initial check response (not streaming) to see if alive
        requests.get("http://127.0.0.1:11434", timeout=2)
    except Exception:
        return jsonify({
            "error": "Ollama Not Detected",
            "instruction": "Please install and run Ollama with Phi3.5 to enable the KAVACH AI Assistant. Download at ollama.com."
        }), 503

    rag_context = get_rag_context(session['user_id'], asset_id)
    
    system_prompt = (
        "You are the KAVACH AI Security Assistant. Provide genuine, expert cybersecurity advice based on the provided context.\n"
        "STRICT RULES:\n"
        "- Provide the smallest, most concise answer possible. Do NOT write long paragraphs.\n"
        "- Give exactly 1 or 2 extremely short bullet points.\n"
        "- Give genuine advice, not just a generic remediation step.\n"
        "- Use short, punchy sentences. No filler, no preamble, no pleasantries.\n"
        "- Action and Result first. Do not explain unless explicitly asked.\n"
        "- Compress English explanations into terse, mature security terminology.\n"
        "- Maintain proper markdown code blocks when necessary.\n\n"
        f"CONTEXT:\n{rag_context}"
    )

    def generate():
        payload = {
            "model": "phi3.5",
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message}
            ],
            "stream": True
        }
        
        try:
            with requests.post(ollama_url, json=payload, stream=True) as r:
                for line in r.iter_lines():
                    if line:
                        chunk = json.loads(line.decode('utf-8'))
                        if 'message' in chunk and 'content' in chunk['message']:
                            yield chunk['message']['content']
        except Exception as e:
            yield f"Error connecting to AI: {str(e)}"

    return app.response_class(generate(), mimetype='text/plain')

# ---------------------------------------------------------------------------
# API ROUTES
# ---------------------------------------------------------------------------

@app.route('/api/my-domains', methods=['GET'])
@login_required
def api_my_domains():
    domains = Domain.query.filter_by(user_id=session['user_id']).order_by(Domain.added_at.desc()).all()
    return jsonify([d.to_dict() for d in domains])

@app.route('/internal/emit', methods=['POST'])
def internal_emit():
    data = request.json
    socketio.emit(data['event'], data['payload'], namespace='/')
    return jsonify({"status": "ok"})

@app.route('/api/discover', methods=['POST'])
@login_required
def api_discover():
    data = request.json
    raw_domain = data.get('domain', '')
    
    if not raw_domain:
        return jsonify({"error": "domain required"}), 400
        
    import re
    # Clean up the domain
    domain_name = raw_domain.strip().lower()
    domain_name = re.sub(r'^https?://', '', domain_name)
    domain_name = domain_name.split('/')[0]
    domain_name = domain_name.split(':')[0]
    if domain_name.startswith('www.'):
        domain_name = domain_name[4:]
        
    if not domain_name:
        return jsonify({"error": "invalid domain"}), 400
        
    existing = Domain.query.filter_by(user_id=session['user_id'], domain_name=domain_name).first()
    
    if existing:
        domain_id = existing.id
        existing.discovery_status = 'discovering'
    else:
        new_domain = Domain(user_id=session['user_id'], domain_name=domain_name, discovery_status='discovering')
        db.session.add(new_domain)
        db.session.commit()
        domain_id = new_domain.id
        
    db.session.commit()
    
    from tasks import background_discovery_task
    # Launch huey thread
    background_discovery_task(session['user_id'], domain_id, domain_name)
    
    return jsonify({
        "status": "started",
        "domain_id": domain_id,
        "domain_name": domain_name
    })

@app.route('/api/discovery-assets/<int:domain_id>', methods=['GET'])
@login_required
def api_discovery_assets(domain_id):
    dom = Domain.query.filter_by(id=domain_id, user_id=session['user_id']).first()
    if not dom:
        return jsonify({"error": "Unauthorized"}), 403
        
    assets = Asset.query.filter_by(domain_id=domain_id).all()
    
    active = [a.to_dict() for a in assets if a.pqc_status != 'suspicious']
    suspicious = [a.to_dict() for a in assets if a.pqc_status == 'suspicious']
    
    return jsonify({
        "domain_name": dom.domain_name,
        "discovery_status": dom.discovery_status,
        "active": active,
        "suspicious": suspicious,
        "counts": {
            "active": len(active),
            "suspicious": len(suspicious)
        }
    })

def geolocate_ips(domain_id):
    """
    Offline geolocation for all unique IPs for a domain using geoip2 and GeoLite2-City database.
    Updates the assets table with latitude, longitude, country, city.
    """
    assets = Asset.query.filter(Asset.domain_id == domain_id, Asset.ip_address.isnot(None), Asset.latitude.is_(None)).all()
    
    ips = list(set([a.ip_address for a in assets if a.ip_address]))
    if not ips:
        return
        
    db_path = os.path.join(app.root_path, 'GeoLite2-City.mmdb')
    if not os.path.exists(db_path):
        print(f"Warning: GeoLite2-City.mmdb not found at {db_path}. Skipping geolocation.")
        return
        
    try:
        reader = geoip2.database.Reader(db_path)
        count = 0
        for ip_string in ips:
            try:
                # Use only the first IP in the list for geolocation
                ip = ip_string.split(',')[0].strip()
                response = reader.city(ip)
                lat = response.location.latitude
                lon = response.location.longitude
                country = response.country.name
                city = response.city.name
                
                assets_to_update = [a for a in assets if a.ip_address == ip_string]
                for a in assets_to_update:
                    a.latitude = lat
                    a.longitude = lon
                    a.country = country
                    a.city = city
                count += 1
            except geoip2.errors.AddressNotFoundError:
                pass
            except Exception as inner_e:
                print(f"Error geolocating {ip_string}: {inner_e}")
                
        db.session.commit()
        print(f"Offline geolocated {count} IPs for domain_id={domain_id}")
    except Exception as e:
        print(f"Offline Geolocation failed: {e}")
    finally:
        try:
            reader.close()
        except:
            pass

@app.route('/api/scan', methods=['POST'])
@login_required
def api_scan():
    data = request.json
    domain_id = data.get('domain_id')
    subdomains = data.get('subdomains') # list of dicts
    
    # Ownership verify
    domain = Domain.query.filter_by(id=domain_id, user_id=session['user_id']).first()
    
    if not domain:
        return jsonify({"error": "Unauthorized"}), 403
        
    from tasks import background_scan_task
    # Launch huey thread
    background_scan_task(domain_id, subdomains)
    
    return jsonify({"status": "started", "domain_id": domain_id, "total": len(subdomains)})

@app.route('/api/scan/progress/<int:domain_id>', methods=['GET'])
@login_required
def api_scan_progress(domain_id):
    domain = Domain.query.filter_by(id=domain_id, user_id=session['user_id']).first()
    if not domain:
        return jsonify({"error": "Unauthorized"}), 403
        
    assets_count = Asset.query.filter_by(domain_id=domain_id).count()
    
    return jsonify({
        "status": domain.status,
        "completed": assets_count
    })

@app.route('/api/dashboard', methods=['GET'])
@login_required
def api_dashboard():
    user_id = session['user_id']
    domain_id = request.args.get('domain_id')
    
    if domain_id:
        domains_count = 1
        assets = Asset.query.join(Domain).filter(Domain.user_id == user_id, Domain.id == domain_id, Asset.pqc_score.isnot(None)).all()
    else:
        domains_count = Domain.query.filter_by(user_id=user_id).count()
        assets = Asset.query.join(Domain).filter(Domain.user_id == user_id, Asset.pqc_score.isnot(None)).all()
    
    total_assets = len(assets)
    failed = len([a for a in assets if a.scan_error])
    valid = total_assets - failed
    
    elite = len([a for a in assets if a.pqc_score and a.pqc_score > 700])
    critical = len([a for a in assets if a.risk_level == 'critical'])
    
    # Process chart data
    risk_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0}
    type_counts = {"API": 0, "Web App": 0, "Server": 0, "Other": 0}
    
    for a in assets:
        if a.scan_error: continue
        
        # Risk levels
        r = (a.risk_level or '').lower()
        if r == 'critical': risk_counts['Critical'] += 1
        elif r == 'high': risk_counts['High'] += 1
        elif r == 'medium': risk_counts['Medium'] += 1
        elif r == 'low': risk_counts['Low'] += 1
        else: risk_counts['Unknown'] += 1
            
        # Asset Types (heuristic based on server_software)
        sw = (a.server_software or '').lower()
        if 'api' in sw or 'node' in sw or 'express' in sw: type_counts['API'] += 1
        elif 'nginx' in sw or 'apache' in sw or 'iis' in sw: type_counts['Web App'] += 1
        elif sw: type_counts['Server'] += 1
        else: type_counts['Other'] += 1
    
    return jsonify({
        "domains": domains_count,
        "total_assets": valid,
        "elite_pqc": elite,
        "critical_risks": critical,
        "risk_distribution": risk_counts,
        "asset_types": type_counts
    })

@app.route('/api/cbom', methods=['GET'])
@app.route('/api/cbom/<int:domain_id>', methods=['GET'])
@login_required
def api_cbom(domain_id=None):
    if not domain_id:
        domain_id = request.args.get('domain_id')
    
    if domain_id:
        d = Domain.query.filter_by(id=domain_id, user_id=session['user_id']).first()
        if not d:
            return jsonify({"error": "Unauthorized"}), 403
            
        assets = Asset.query.filter(Asset.domain_id == domain_id, Asset.pqc_score.isnot(None)).all()
    else:
        assets = Asset.query.join(Domain).filter(Domain.user_id == session['user_id'], Asset.pqc_score.isnot(None)).all()
    
    cbom_data = build_cbom_data([a.to_dict() for a in assets])
    return jsonify(cbom_data)

@app.route('/api/posture', methods=['GET'])
@app.route('/api/posture/<int:domain_id>', methods=['GET'])
@login_required
def api_posture(domain_id=None):
    if not domain_id:
        domain_id = request.args.get('domain_id')
    
    if domain_id:
        d = Domain.query.filter_by(id=domain_id, user_id=session['user_id']).first()
        if not d:
            return jsonify({"error": "Unauthorized"}), 403
        assets = Asset.query.filter(Asset.domain_id == domain_id, Asset.pqc_score.isnot(None)).all()
    else:
        assets = Asset.query.join(Domain).filter(Domain.user_id == session['user_id'], Asset.pqc_score.isnot(None)).all()
    
    # Augment data with PQC breakdown and recommendation
    augmented_assets = []
    for a in assets:
        asset_dict = a.to_dict()
        if not asset_dict.get('scan_error'):
            pqc_data = check_pqc(
                asset_dict.get('tls_version'),
                asset_dict.get('cipher_suite'),
                asset_dict.get('key_length'),
                asset_dict.get('key_type')
            )
            asset_dict['recommendation'] = pqc_data.get('recommendation')
            asset_dict['pqc_details'] = pqc_data.get('details')
        else:
            asset_dict['recommendation'] = "Resolve scan error to determine cryptographic posture."
            asset_dict['pqc_details'] = {}
        augmented_assets.append(asset_dict)
        
    return jsonify(augmented_assets)

@app.route('/api/rating', methods=['GET'])
@app.route('/api/rating/<int:domain_id>', methods=['GET'])
@login_required
def api_rating(domain_id=None):
    if not domain_id:
        domain_id = request.args.get('domain_id')
    
    if domain_id:
        d = Domain.query.filter_by(id=domain_id, user_id=session['user_id']).first()
        if not d:
            return jsonify({"error": "Unauthorized"}), 403
        assets = Asset.query.filter(Asset.domain_id == domain_id, Asset.scan_error.is_(None), Asset.pqc_score.isnot(None)).all()
    else:
        assets = Asset.query.join(Domain).filter(Domain.user_id == session['user_id'], Asset.scan_error.is_(None), Asset.pqc_score.isnot(None)).all()
    
    if not assets:
        return jsonify({"average_score": 0, "rating": "Unknown"})
        
    avg = sum([a.pqc_score for a in assets]) / len(assets)
    
    rating = "Critical"
    if avg > 700: rating = "Elite"
    elif avg >= 400: rating = "Standard"
    elif avg >= 100: rating = "Legacy"
    
    return jsonify({
        "average_score": int(avg),
        "rating": rating
    })

@app.route('/api/attestation', methods=['GET'])
@app.route('/api/attestation/<int:domain_id>', methods=['GET'])
@login_required
def api_attestation(domain_id=None):
    if not domain_id:
        domain_id_str = request.args.get('domain_id')
        if domain_id_str and domain_id_str != 'none':
            domain_id = int(domain_id_str)

    if domain_id:
        domain = Domain.query.filter_by(id=domain_id, user_id=session['user_id']).first()
        if not domain:
            return jsonify({"error": "Unauthorized"}), 403
            
        assets = Asset.query.filter(Asset.domain_id == domain_id, Asset.scan_error.is_(None), Asset.pqc_score.isnot(None)).all()
        target_name = domain.domain_name
        download_name = f"kavach_attestation_{domain.domain_name}.pdf"
    else:
        assets = Asset.query.join(Domain).filter(Domain.user_id == session['user_id'], Asset.scan_error.is_(None), Asset.pqc_score.isnot(None)).all()
        target_name = "Global Enterprise Infrastructure"
        download_name = "kavach_attestation_global.pdf"
        
    if not assets:
        avg = 0
    else:
        avg = int(sum([a.pqc_score for a in assets]) / len(assets))
        
    rating = "Critical Action Required"
    color_hex = '#ef4444' # red
    
    if avg > 700: 
        rating = "Elite PQC-Ready"
        color_hex = '#22c55e' # green
    elif avg >= 400: 
        rating = "Standard Compliant"
        color_hex = '#eab308' # yellow
    elif avg >= 100: 
        rating = "Legacy Vulnerable"
        color_hex = '#f97316' # orange
        
    # Generate PDF in memory using Platypus
    buffer = io.BytesIO()
    
    # We use portrait (letter) for a formal letter
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=50, leftMargin=50, topMargin=50, bottomMargin=50)
    elements = []
    
    styles = getSampleStyleSheet()
    
    # Add a huge title
    title_style = ParagraphStyle(
        'MainTitle',
        parent=styles['Heading1'],
        fontSize=28,
        textColor=colors.HexColor('#800000'), # Maroon
        alignment=1, # Center
        spaceAfter=30
    )
    
    # Subtitle
    subtitle_style = ParagraphStyle(
        'Subtitle',
        parent=styles['Normal'],
        fontSize=14,
        textColor=colors.HexColor('#666666'),
        alignment=1,
        spaceAfter=40
    )
    
    body_style = ParagraphStyle(
        'BodyText',
        parent=styles['Normal'],
        fontSize=12,
        leading=18,
        spaceAfter=20
    )
    
    score_style = ParagraphStyle(
        'ScoreText',
        parent=styles['Heading2'],
        fontSize=36,
        textColor=colors.HexColor(color_hex),
        alignment=1,
        spaceAfter=10
    )
    
    rating_label_style = ParagraphStyle(
        'RatingLabel',
        parent=styles['Normal'],
        fontSize=16,
        textColor=colors.HexColor('#333333'),
        alignment=1,
        spaceAfter=40
    )
    
    # Building the formal letter
    elements.append(Paragraph("<b><font color='#800000'>KAVACH</font></b> SEAL OF ATTESTATION", title_style))
    elements.append(Paragraph(f"Official Cyber Security Rating Certificate", subtitle_style))
    
    elements.append(Paragraph(f"This document certifies that the cryptographic posture of <b>{target_name}</b> has been audited by the KAVACH platform. This audit evaluated the TLS protocol implementations, Cipher Suites, Key lengths, and Post-Quantum Cryptography (PQC) readiness of {len(assets)} discovered assets.", body_style))
    
    elements.append(Paragraph(f"As of <b>{datetime.now().strftime('%B %d, %Y')}</b>, the infrastructure has achieved an overall enterprise security score of:", body_style))
    
    elements.append(Spacer(1, 20))
    elements.append(Paragraph(f"<b>{avg} / 1000</b>", score_style))
    elements.append(Paragraph(f"({rating})", rating_label_style))
    elements.append(Spacer(1, 20))
    
    footer_text = "This certificate is automatically generated via deep cryptographic telemetry. "
    if avg > 700:
        footer_text += "This network demonstrates exceptional forward-thinking security and resilience against theoretical 'Store-Now-Decrypt-Later' quantum computing attacks."
    elif avg >= 400:
        footer_text += "This network meets standard modern security baselines, but requires migration to ML-KEM or Kyber algorithms to achieve true Post-Quantum resistance."
    else:
        footer_text += "This network contains severe vulnerabilities or legacy cryptographic algorithms. Urgent remediation is strictly advised."
        
    elements.append(Paragraph(footer_text, body_style))
    
    elements.append(Spacer(1, 60))
    
    # Signature line
    sign_table = Table([
        ["_________________________"],
        ["KAVACH Automated Auditing Engine"]
    ], colWidths=[300])
    sign_table.setStyle(TableStyle([
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('TEXTCOLOR', (0,0), (-1,-1), colors.HexColor('#333333')),
        ('FONTNAME', (0,0), (-1,-1), 'Helvetica-Oblique')
    ]))
    elements.append(sign_table)
    
    # Build Document
    doc.build(elements)
    buffer.seek(0)
    
    return send_file(
        buffer,
        as_attachment=True,
        download_name=download_name,
        mimetype='application/pdf'
    )

@app.route('/api/report', methods=['GET'])
@app.route('/api/report/<int:domain_id>', methods=['GET'])
@login_required
def api_report(domain_id=None):
    if not domain_id:
        domain_id_str = request.args.get('domain_id')
        if domain_id_str and domain_id_str != 'none':
            domain_id = int(domain_id_str)

    if domain_id:
        domain = Domain.query.filter_by(id=domain_id, user_id=session['user_id']).first()
        if not domain:
            return jsonify({"error": "Unauthorized"}), 403
            
        assets_query = Asset.query.filter_by(domain_id=domain_id).all()
        report_title = f"KAVACH Security Report: {domain.domain_name}"
        download_name = f"kavach_report_{domain.domain_name}.pdf"
    else:
        assets_query = Asset.query.join(Domain).filter(Domain.user_id == session['user_id']).all()
        report_title = "KAVACH Security Report: All Domains"
        download_name = "kavach_report_all_domains.pdf"
        
    # Generate PDF in memory using Platypus
    buffer = io.BytesIO()
    
    # Convert objects to dicts so that .get() works for calculating missing data
    assets = [a.to_dict() for a in assets_query]
    
    # We use landscape to fit all the columns
    doc = SimpleDocTemplate(buffer, pagesize=landscape(letter), rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=30)
    elements = []
    
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'MainTitle',
        parent=styles['Heading1'],
        fontSize=18,
        textColor=colors.HexColor('#800000'), # Maroon
        spaceAfter=14
    )
    subtitle_style = ParagraphStyle(
        'Subtitle',
        parent=styles['Normal'],
        fontSize=12,
        textColor=colors.HexColor('#333333'),
        spaceAfter=14
    )
    
    elements.append(Paragraph(report_title, title_style))
    elements.append(Paragraph(f"Generated automatically on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", subtitle_style))
    
    # Summary Metrics
    total_assets = len(assets)
    failed_assets = len([a for a in assets if a.get('scan_error')])
    critical_assets = len([a for a in assets if a.get('risk_level') == 'critical'])
    elite_assets = len([a for a in assets if a.get('pqc_score') and a.get('pqc_score') > 700])
    
    summary_data = [
        ['Total Assets Discovered', 'Failed Scans', 'Critical Risks Found', 'Elite PQC Rating'],
        [str(total_assets), str(failed_assets), str(critical_assets), str(elite_assets)]
    ]
    
    summary_table = Table(summary_data, colWidths=[150, 120, 150, 150])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#800000')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#FDFDFD')),
        ('TEXTCOLOR', (0, 1), (-1, 1), colors.black),
        ('FONTNAME', (0, 1), (-1, 1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, 1), 14),
        ('GRID', (0,0), (-1,-1), 1, colors.HexColor('#DDDDDD')),
    ]))
    
    elements.append(summary_table)
    elements.append(Spacer(1, 20))
    
    elements.append(Paragraph("Asset Inventory Details", ParagraphStyle('Heading2', parent=styles['Heading2'], textColor=colors.HexColor('#800000'), spaceAfter=10)))
    
    # Asset List Table
    headers = ['#', 'Subdomain', 'IP Address', 'TLS Version', 'Cipher Suite', 'Risk Level', 'PQC Score']
    data = [headers]
    
    for index, a in enumerate(assets):
        row = [
            str(index + 1),
            a.get('subdomain') or 'N/A',
            a.get('ip_address') or 'N/A',
            a.get('tls_version') or 'N/A',
            (a.get('cipher_suite') or 'N/A')[:25] + ('...' if a.get('cipher_suite') and len(a.get('cipher_suite')) > 25 else ''),
            (a.get('risk_level') or 'Unknown').title() if a.get('scan_error') is None else "Error",
            str(a.get('pqc_score') or '0')
        ]
        data.append(row)
        
    # Column widths (Total width ~ 730 points for landscape letter)
    col_widths = [30, 200, 100, 70, 180, 80, 70]
    
    asset_table = Table(data, colWidths=col_widths, repeatRows=1)
    
    # Table Styling
    ts = TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#800000')), # Maroon header
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#FFD700')), # Gold text
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('ALIGN', (0, 0), (0, -1), 'CENTER'), # Center align ID
        ('ALIGN', (5, 0), (6, -1), 'CENTER'), # Center align Risk and Score
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('TOPPADDING', (0, 0), (-1, 0), 8),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CCCCCC')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ])
    
    # Alternating row colors
    for i in range(1, len(data)):
        if i % 2 == 0:
            ts.add('BACKGROUND', (0, i), (-1, i), colors.HexColor('#F9F9F9'))
            
    asset_table.setStyle(ts)
    elements.append(asset_table)
    
    # Build Document
    doc.build(elements)
    buffer.seek(0)
    
    return send_file(
        buffer,
        as_attachment=True,
        download_name=download_name,
        mimetype='application/pdf'
    )

@app.route('/api/export', methods=['GET'])
@app.route('/api/export/<int:domain_id>', methods=['GET'])
@login_required
def api_export(domain_id=None):
    fmt = request.args.get('format', 'json').lower()
    
    if not domain_id:
        domain_id_str = request.args.get('domain_id')
        if domain_id_str and domain_id_str != 'none':
            domain_id = int(domain_id_str)

    if domain_id:
        domain = Domain.query.filter_by(id=domain_id, user_id=session['user_id']).first()
        if not domain:
            return jsonify({"error": "Unauthorized"}), 403
        assets = Asset.query.filter_by(domain_id=domain_id).all()
        prefix = domain.domain_name
    else:
        assets = Asset.query.join(Domain).filter(Domain.user_id == session['user_id']).all()
        prefix = "all_domains"
        
    asset_dicts = [a.to_dict() for a in assets]
    
    if fmt == 'csv':
        if not asset_dicts:
            return "No data", 404
        
        si = io.StringIO()
        keys = list(asset_dicts[0].keys())
        cw = csv.DictWriter(si, fieldnames=keys)
        cw.writeheader()
        cw.writerows(asset_dicts)
        
        mem = io.BytesIO()
        mem.write(si.getvalue().encode('utf-8'))
        mem.seek(0)
        
        return send_file(
            mem,
            mimetype='text/csv',
            as_attachment=True,
            download_name=f"kavach_export_{prefix}.csv"
        )
    else:
        # JSON
        return jsonify(asset_dicts)

if __name__ == '__main__':
    import urllib3
    import subprocess
    import sys
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Launch Huey worker as a SEPARATE process so it is NOT affected by eventlet monkey_patch
    print("Starting background Huey task consumer (subprocess)...")
    huey_env = {**os.environ, 'KAVACH_NO_PATCH': '1'}
    huey_proc = subprocess.Popen(
        [sys.executable, "-m", "huey.bin.huey_consumer", "tasks.huey", "-w", "2", "-k", "thread"],
        cwd=os.path.dirname(os.path.abspath(__file__)),
        env=huey_env
    )
    
    try:
        # We disable the reloader to prevent WinError 10038 caused by background threads during live-reload
        socketio.run(app, debug=True, use_reloader=False, port=int(os.environ.get('PORT', 5000)), host='0.0.0.0')
    finally:
        huey_proc.terminate()

