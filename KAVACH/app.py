import os
import requests
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, send_file
from werkzeug.security import generate_password_hash, check_password_hash
import threading
import io
import time
from datetime import datetime
from functools import wraps

from database import get_db, init_db
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

# Initialize database on startup
# This ensures tables are created even when running with Gunicorn on Render
with app.app_context():
    init_db()

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
        
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['user_name'] = user['name']
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
        
        conn = get_db()
        try:
            conn.execute('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', (name, email, hashed_pw))
            conn.commit()
            
            # auto login
            user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
            session['user_id'] = user['id']
            session['user_name'] = user['name']
            conn.close()
            return redirect(url_for('index'))
            
        except conn.IntegrityError:
            conn.close()
            return render_template('register.html', error='Email already exists')
            
    return render_template('register.html')

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

# ---------------------------------------------------------------------------
# API ROUTES
# ---------------------------------------------------------------------------

@app.route('/api/my-domains', methods=['GET'])
@login_required
def api_my_domains():
    conn = get_db()
    domains = conn.execute('SELECT * FROM domains WHERE user_id = ? ORDER BY added_at DESC', (session['user_id'],)).fetchall()
    conn.close()
    return jsonify([dict(d) for d in domains])

@app.route('/api/discover', methods=['POST'])
@login_required
def api_discover():
    data = request.json
    raw_domain = data.get('domain', '')
    
    if not raw_domain:
        return jsonify({"error": "domain required"}), 400
        
    import re
    # Clean up the domain (remove scheme, path, port, and www.)
    domain_name = raw_domain.strip().lower()
    domain_name = re.sub(r'^https?://', '', domain_name)
    domain_name = domain_name.split('/')[0]
    domain_name = domain_name.split(':')[0]
    if domain_name.startswith('www.'):
        domain_name = domain_name[4:]
        
    if not domain_name:
        return jsonify({"error": "invalid domain"}), 400
        
    discovery_result = get_subdomains(domain_name)
    
    conn = get_db()
    cursor = conn.cursor()
    
    existing = cursor.execute('SELECT id FROM domains WHERE user_id = ? AND domain_name = ?', 
                             (session['user_id'], domain_name)).fetchone()
    if existing:
        domain_id = existing['id']
        cursor.execute("UPDATE domains SET status = 'discovered' WHERE id = ?", (domain_id,))
    else:
        cursor.execute('INSERT INTO domains (user_id, domain_name, status) VALUES (?, ?, ?)', 
                      (session['user_id'], domain_name, 'discovered'))
        domain_id = cursor.lastrowid
        
    conn.commit()
    conn.close()
    
    return jsonify({
        "domain_id": domain_id,
        "active": discovery_result.get('active', []),
        "suspicious": discovery_result.get('suspicious', []),
        "unresolvable": discovery_result.get('unresolvable', []),
        "external": discovery_result.get('external', []),
        "counts": discovery_result.get('counts', {})
    })

def geolocate_ips(domain_id):
    """
    Batch geolocate all unique IPs for a domain using ip-api.com (free, 100 IPs per batch).
    Updates the assets table with latitude, longitude, country, city.
    """
    conn = get_db()
    assets = conn.execute(
        'SELECT DISTINCT ip_address FROM assets WHERE domain_id = ? AND ip_address IS NOT NULL AND latitude IS NULL',
        (domain_id,)
    ).fetchall()
    
    ips = [a['ip_address'] for a in assets if a['ip_address']]
    if not ips:
        conn.close()
        return
    
    # ip-api.com batch endpoint: POST up to 100 IPs at once
    try:
        batch_url = 'http://ip-api.com/batch?fields=query,lat,lon,country,city,status'
        payload = [{'query': ip} for ip in ips[:100]]
        
        res = requests.post(batch_url, json=payload, timeout=15)
        if res.status_code == 200:
            results = res.json()
            for item in results:
                if item.get('status') == 'success':
                    conn.execute(
                        'UPDATE assets SET latitude = ?, longitude = ?, country = ?, city = ? WHERE domain_id = ? AND ip_address = ?',
                        (item.get('lat'), item.get('lon'), item.get('country'), item.get('city'), domain_id, item.get('query'))
                    )
            conn.commit()
            print(f"Geolocated {len(results)} IPs for domain_id={domain_id}")
    except Exception as e:
        print(f"Geolocation failed: {e}")
    
    conn.close()

def background_scan_job(domain_id, subdomains):
    """
    Background worker that runs the deep scan on selected subdomains
    """
    conn = get_db()
    conn.execute('UPDATE domains SET status = ? WHERE id = ?', ('scanning', domain_id))
    conn.commit()
    
    for sub in subdomains:
        subdomain = sub.get('subdomain')
        ip_address = sub.get('ip_address')
        server = sub.get('server_software')
        
        # 1. Start TLS Scan
        scan_data = scan_subdomain(subdomain)
        
        # 2. Score via PQC logic
        if not scan_data.get('error'):
            pqc_data = check_pqc(
                scan_data.get('tls_version'),
                scan_data.get('cipher_suite'),
                scan_data.get('key_length')
            )
        else:
            pqc_data = {
                "pqc_score": 0, "pqc_status": "Failed",
                "risk_level": "unknown", "color": "", "recommendation": ""
            }
            
        # 3. Save to database
        conn.execute('''
            INSERT INTO assets (
                domain_id, subdomain, ip_address, tls_version, cipher_suite, key_length,
                cert_expiry, cert_authority, cert_common_name, cert_fingerprint,
                server_software, pqc_status, pqc_score, risk_level, scan_error
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            domain_id, subdomain, ip_address, scan_data.get('tls_version'),
            scan_data.get('cipher_suite'), scan_data.get('key_length'),
            scan_data.get('cert_expiry'), scan_data.get('cert_authority'),
            scan_data.get('cert_common_name'), scan_data.get('cert_fingerprint'),
            server, pqc_data.get('pqc_status'), pqc_data.get('pqc_score'),
            pqc_data.get('risk_level'), scan_data.get('error')
        ))
        conn.commit()
        
    # Mark as completed
    conn.execute("UPDATE domains SET status = 'completed', last_scanned = CURRENT_TIMESTAMP WHERE id = ?", (domain_id,))
    conn.commit()
    conn.close()
    
    # Geolocate all IPs after scan is done
    geolocate_ips(domain_id)

@app.route('/api/scan', methods=['POST'])
@login_required
def api_scan():
    data = request.json
    domain_id = data.get('domain_id')
    subdomains = data.get('subdomains') # list of dicts
    
    # Ownership verify
    conn = get_db()
    domain = conn.execute('SELECT * FROM domains WHERE id = ? AND user_id = ?', (domain_id, session['user_id'])).fetchone()
    conn.close()
    
    if not domain:
        return jsonify({"error": "Unauthorized"}), 403
        
    # Launch background thread
    t = threading.Thread(target=background_scan_job, args=(domain_id, subdomains))
    t.start()
    
    return jsonify({"status": "started", "domain_id": domain_id, "total": len(subdomains)})

@app.route('/api/scan/progress/<int:domain_id>', methods=['GET'])
@login_required
def api_scan_progress(domain_id):
    conn = get_db()
    domain = conn.execute('SELECT status FROM domains WHERE id = ? AND user_id = ?', (domain_id, session['user_id'])).fetchone()
    if not domain:
        conn.close()
        return jsonify({"error": "Unauthorized"}), 403
        
    assets = conn.execute('SELECT count(*) as c FROM assets WHERE domain_id = ?', (domain_id,)).fetchone()
    conn.close()
    
    return jsonify({
        "status": domain['status'],
        "completed": assets['c']
    })

@app.route('/api/dashboard', methods=['GET'])
@login_required
def api_dashboard():
    conn = get_db()
    user_id = session['user_id']
    domain_id = request.args.get('domain_id')
    
    if domain_id:
        domains_count = 1
        assets = conn.execute("""
            SELECT a.pqc_score, a.risk_level, a.scan_error, a.server_software 
            FROM assets a
            JOIN domains d ON a.domain_id = d.id
            WHERE d.user_id = ? AND d.id = ?
        """, (user_id, domain_id)).fetchall()
    else:
        domains_count = conn.execute("SELECT count(*) as c FROM domains WHERE user_id = ?", (user_id,)).fetchone()['c']
        assets = conn.execute("""
            SELECT a.pqc_score, a.risk_level, a.scan_error, a.server_software 
            FROM assets a
            JOIN domains d ON a.domain_id = d.id
            WHERE d.user_id = ?
        """, (user_id,)).fetchall()
    conn.close()
    
    total_assets = len(assets)
    failed = len([a for a in assets if a['scan_error']])
    valid = total_assets - failed
    
    elite = len([a for a in assets if a['pqc_score'] and a['pqc_score'] > 700])
    critical = len([a for a in assets if a['risk_level'] == 'critical'])
    
    # Process chart data
    risk_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0}
    type_counts = {"API": 0, "Web App": 0, "Server": 0, "Other": 0}
    
    for a in assets:
        if a['scan_error']: continue
        
        # Risk levels
        r = (a['risk_level'] or '').lower()
        if r == 'critical': risk_counts['Critical'] += 1
        elif r == 'high': risk_counts['High'] += 1
        elif r == 'medium': risk_counts['Medium'] += 1
        elif r == 'low': risk_counts['Low'] += 1
        else: risk_counts['Unknown'] += 1
            
        # Asset Types (heuristic based on server_software)
        sw = (a['server_software'] or '').lower()
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
    conn = get_db()
    
    if domain_id:
        # verify
        d = conn.execute("SELECT * FROM domains WHERE id = ? AND user_id = ?", (domain_id, session['user_id'])).fetchone()
        if not d:
            conn.close()
            return jsonify({"error": "Unauthorized"}), 403
            
        assets = conn.execute("SELECT * FROM assets WHERE domain_id = ?", (domain_id,)).fetchall()
    else:
        assets = conn.execute("""
            SELECT assets.* FROM assets
            JOIN domains ON assets.domain_id = domains.id
            WHERE domains.user_id = ?
        """, (session['user_id'],)).fetchall()
    conn.close()
    
    cbom_data = build_cbom_data([dict(a) for a in assets])
    return jsonify(cbom_data)

@app.route('/api/posture', methods=['GET'])
@app.route('/api/posture/<int:domain_id>', methods=['GET'])
@login_required
def api_posture(domain_id=None):
    if not domain_id:
        domain_id = request.args.get('domain_id')
    conn = get_db()
    
    if domain_id:
        d = conn.execute("SELECT * FROM domains WHERE id = ? AND user_id = ?", (domain_id, session['user_id'])).fetchone()
        if not d:
            conn.close()
            return jsonify({"error": "Unauthorized"}), 403
        assets = conn.execute("""
            SELECT subdomain, pqc_status, pqc_score, tls_version, cipher_suite, 
                   scan_error, ip_address, scanned_at, server_software,
                   latitude, longitude, country, city, key_length, cert_authority, cert_expiry
            FROM assets WHERE domain_id = ?
        """, (domain_id,)).fetchall()
    else:
        assets = conn.execute("""
            SELECT a.subdomain, a.pqc_status, a.pqc_score, a.tls_version, 
                   a.cipher_suite, a.scan_error, a.ip_address, a.scanned_at, a.server_software,
                   a.latitude, a.longitude, a.country, a.city, a.key_length, a.cert_authority, a.cert_expiry
            FROM assets a
            JOIN domains d ON a.domain_id = d.id
            WHERE d.user_id = ?
        """, (session['user_id'],)).fetchall()
    
    conn.close()
    
    # Augment data with PQC breakdown and recommendation
    augmented_assets = []
    for a in assets:
        asset_dict = dict(a)
        if not asset_dict.get('scan_error'):
            pqc_data = check_pqc(
                asset_dict.get('tls_version'),
                asset_dict.get('cipher_suite'),
                asset_dict.get('key_length')
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
    conn = get_db()
    
    if domain_id:
        d = conn.execute("SELECT * FROM domains WHERE id = ? AND user_id = ?", (domain_id, session['user_id'])).fetchone()
        if not d:
            conn.close()
            return jsonify({"error": "Unauthorized"}), 403
        assets = conn.execute("""
            SELECT pqc_score FROM assets WHERE domain_id = ? AND scan_error IS NULL
        """, (domain_id,)).fetchall()
    else:
        assets = conn.execute("""
            SELECT a.pqc_score FROM assets a
            JOIN domains d ON a.domain_id = d.id
            WHERE d.user_id = ? AND a.scan_error IS NULL
        """, (session['user_id'],)).fetchall()
    conn.close()
    
    if not assets:
        return jsonify({"average_score": 0, "rating": "Unknown"})
        
    avg = sum([a['pqc_score'] for a in assets]) / len(assets)
    
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

    conn = get_db()
    if domain_id:
        domain = conn.execute("SELECT * FROM domains WHERE id = ? AND user_id = ?", (domain_id, session['user_id'])).fetchone()
        if not domain:
            conn.close()
            return jsonify({"error": "Unauthorized"}), 403
            
        assets = conn.execute("SELECT pqc_score FROM assets WHERE domain_id = ? AND scan_error IS NULL", (domain_id,)).fetchall()
        target_name = domain['domain_name']
        download_name = f"kavach_attestation_{domain['domain_name']}.pdf"
    else:
        assets = conn.execute("""
            SELECT a.pqc_score FROM assets a
            JOIN domains d ON a.domain_id = d.id
            WHERE d.user_id = ? AND a.scan_error IS NULL
        """, (session['user_id'],)).fetchall()
        target_name = "Global Enterprise Infrastructure"
        download_name = "kavach_attestation_global.pdf"
        
    conn.close()
    
    if not assets:
        avg = 0
    else:
        avg = int(sum([a['pqc_score'] for a in assets]) / len(assets))
        
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

    conn = get_db()
    if domain_id:
        domain = conn.execute("SELECT * FROM domains WHERE id = ? AND user_id = ?", (domain_id, session['user_id'])).fetchone()
        if not domain:
            conn.close()
            return jsonify({"error": "Unauthorized"}), 403
            
        assets = conn.execute("SELECT * FROM assets WHERE domain_id = ?", (domain_id,)).fetchall()
        report_title = f"KAVACH Security Report: {domain['domain_name']}"
        download_name = f"kavach_report_{domain['domain_name']}.pdf"
    else:
        assets = conn.execute("""
            SELECT a.* FROM assets a
            JOIN domains d ON a.domain_id = d.id
            WHERE d.user_id = ?
        """, (session['user_id'],)).fetchall()
        report_title = "KAVACH Security Report: All Domains"
        download_name = "kavach_report_all_domains.pdf"
        
    conn.close()
    
    # Generate PDF in memory using Platypus
    buffer = io.BytesIO()
    
    # Convert sqlite3.Row objects to dicts so that .get() works for calculating missing data
    assets = [dict(a) for a in assets]
    
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

if __name__ == '__main__':
    app.run(debug=True, port=int(os.environ.get('PORT', 5000)), host='0.0.0.0')
