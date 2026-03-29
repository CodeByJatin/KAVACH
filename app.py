from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from database import get_db, init_db
from scanner.discovery import get_subdomains
from scanner.tls_scanner import scan_subdomain
from scanner.pqc_checker import check_pqc
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.enums import TA_CENTER, TA_LEFT
import io
import threading
from datetime import datetime

app = Flask(__name__)
app.secret_key = "kavach-secret-2026"

init_db()

@app.route('/login', methods=['GET'])
def login_get():
    if 'user_id' in session:
        return redirect('/')
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT id, name, password FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()
    db.close()
    
    if user and check_password_hash(user['password'], password):
        session['user_id'] = user['id']
        session['name'] = user['name']
        return redirect('/')
    
    return render_template('login.html', error="Invalid credentials")

@app.route('/register', methods=['GET'])
def register_get():
    if 'user_id' in session:
        return redirect('/')
    return render_template('register.html')

@app.route('/register', methods=['POST'])
def register_post():
    name = request.form.get('name')
    email = request.form.get('email')
    password = request.form.get('password')
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
    existing = cursor.fetchone()
    
    if existing:
        db.close()
        return render_template('register.html', error="Email already registered")
    
    password_hash = generate_password_hash(password)
    cursor.execute(
        'INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
        (name, email, password_hash)
    )
    db.commit()
    
    cursor.execute('SELECT id, name FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()
    db.close()
    
    session['user_id'] = user['id']
    session['name'] = user['name']
    return redirect('/')

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect('/login')

@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect('/login')
    return render_template('pages/home.html', username=session.get('name'))

@app.route('/add-domain')
def add_domain():
    if 'user_id' not in session:
        return redirect('/login')
    return render_template('add_domain.html')

@app.route('/discovery')
def discovery():
    if 'user_id' not in session:
        return redirect('/login')
    domain_id = request.args.get('domain')
    return render_template('pages/discovery.html', username=session.get('name'), domain_id=domain_id)

@app.route('/cbom')
def cbom():
    if 'user_id' not in session:
        return redirect('/login')
    return render_template('cbom.html', username=session.get('name'))

@app.route('/posture')
def posture():
    if 'user_id' not in session:
        return redirect('/login')
    return render_template('posture.html', username=session.get('name'))

@app.route('/rating')
def rating():
    if 'user_id' not in session:
        return redirect('/login')
    return render_template('rating.html', username=session.get('name'))

@app.route('/reporting')
def reporting():
    if 'user_id' not in session:
        return redirect('/login')
    return render_template('reporting.html', username=session.get('name'))

@app.route('/api/report/<int:domain_id>', methods=['GET'])
def api_report(domain_id):
    if 'user_id' not in session:
        return jsonify({'error': 'unauthorized'}), 401
    
    if not verify_domain_ownership(domain_id, session['user_id']):
        return jsonify({'error': 'unauthorized'}), 401
    
    report_type = request.args.get('type', 'full')
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT domain_name FROM domains WHERE id = ?', (domain_id,))
    domain = cursor.fetchone()
    
    if not domain:
        db.close()
        return jsonify({'error': 'Domain not found'}), 404
    
    cursor.execute('SELECT * FROM assets WHERE domain_id = ?', (domain_id,))
    assets = [dict(row) for row in cursor.fetchall()]
    db.close()
    
    domain_name = domain['domain_name']
    total = len(assets)
    elite = sum(1 for a in assets if a.get('pqc_status') == 'Elite-PQC')
    standard = sum(1 for a in assets if a.get('pqc_status') == 'Standard')
    legacy = sum(1 for a in assets if a.get('pqc_status') == 'Legacy')
    critical = sum(1 for a in assets if a.get('pqc_status') == 'Critical')
    
    scores = [a.get('pqc_score', 0) or 0 for a in assets]
    avg_score = round(sum(scores) / len(scores)) if scores else 0
    
    if avg_score > 700:
        overall_status = 'Elite-PQC'
    elif avg_score >= 400:
        overall_status = 'Standard'
    elif avg_score >= 100:
        overall_status = 'Legacy'
    else:
        overall_status = 'Critical'
    
    high_risk = sum(1 for a in assets if a.get('risk_level') in ('high', 'critical'))
    
    RED = colors.HexColor('#DC2626')
    GREEN = colors.HexColor('#16A34A')
    ORANGE = colors.HexColor('#EA580C')
    YELLOW = colors.HexColor('#CA8A04')
    DARK = colors.HexColor('#1e293b')
    
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=0.5*inch, bottomMargin=0.5*inch)
    styles = getSampleStyleSheet()
    elements = []
    
    title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontSize=28, textColor=DARK, alignment=TA_CENTER, spaceAfter=20)
    heading_style = ParagraphStyle('Heading', parent=styles['Heading2'], fontSize=16, textColor=DARK, spaceAfter=12, spaceBefore=12)
    normal_style = styles['Normal']
    
    elements.append(Paragraph('KAVACH', title_style))
    elements.append(Paragraph('Quantum Security Monitor', styles['Heading3']))
    elements.append(Spacer(1, 30))
    elements.append(Paragraph(f'<b>Security Assessment Report</b>', ParagraphStyle('Subtitle', fontSize=18, alignment=TA_CENTER)))
    elements.append(Spacer(1, 20))
    elements.append(Paragraph(f'<b>Domain:</b> {domain_name}', normal_style))
    elements.append(Paragraph(f'<b>Scan Date:</b> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', normal_style))
    elements.append(Paragraph(f'<b>Report Type:</b> {report_type.title()}', normal_style))
    elements.append(Spacer(1, 40))
    
    score_color = GREEN if avg_score > 700 else YELLOW if avg_score >= 400 else ORANGE if avg_score >= 100 else RED
    elements.append(Paragraph(f'<font color="{score_color.hexval()}"><b>PQC Score: {avg_score}/1000</b></font>', ParagraphStyle('Score', fontSize=24, alignment=TA_CENTER)))
    elements.append(Paragraph(f'<b>Status: {overall_status}</b>', ParagraphStyle('Status', fontSize=16, alignment=TA_CENTER, spaceAfter=20)))
    
    elements.append(PageBreak())
    
    elements.append(Paragraph('Executive Summary', heading_style))
    elements.append(Spacer(1, 10))
    summary_data = [
        ['Metric', 'Value'],
        ['Total Assets', str(total)],
        ['High Risk Assets', str(high_risk)],
        ['Overall PQC Score', f'{avg_score}/1000'],
        ['Overall Status', overall_status],
        ['Elite-PQC Ready', str(elite)],
        ['Standard', str(standard)],
        ['Legacy', str(legacy)],
        ['Critical', str(critical)],
    ]
    summary_table = Table(summary_data, colWidths=[2.5*inch, 2*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), DARK),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 30))
    
    elements.append(Paragraph('<b>Top Recommendations:</b>', normal_style))
    recommendations = [
        '1. Upgrade all systems to TLS 1.3 for maximum security',
        '2. Replace weak cipher suites (RC4, 3DES) with AES-GCM',
        '3. Enable post-quantum cryptography where available',
        '4. Regular security assessments and monitoring',
        '5. Certificate renewal before expiry dates'
    ]
    for rec in recommendations:
        elements.append(Paragraph(rec, normal_style))
    
    elements.append(PageBreak())
    
    elements.append(Paragraph('Asset Inventory', heading_style))
    if assets:
        asset_data = [['Subdomain', 'TLS', 'Cipher', 'Key', 'Score', 'Status']]
        for a in assets[:30]:
            asset_data.append([
                (a.get('subdomain') or '-')[:25],
                a.get('tls_version') or '-',
                (a.get('cipher_suite') or '-')[:20],
                str(a.get('key_length') or '-'),
                str(a.get('pqc_score') or 0),
                a.get('pqc_status') or '-'
            ])
        asset_table = Table(asset_data, colWidths=[1.8*inch, 0.6*inch, 1.5*inch, 0.5*inch, 0.5*inch, 0.8*inch])
        asset_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), DARK),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
        ]))
        elements.append(asset_table)
    else:
        elements.append(Paragraph('No assets found.', normal_style))
    
    elements.append(PageBreak())
    
    elements.append(Paragraph('Cryptographic Bill of Materials (CBOM)', heading_style))
    elements.append(Spacer(1, 10))
    
    cipher_usage = {}
    for a in assets:
        cs = a.get('cipher_suite')
        if cs:
            cipher_usage[cs] = cipher_usage.get(cs, 0) + 1
    cipher_list = sorted(cipher_usage.items(), key=lambda x: x[1], reverse=True)[:10]
    
    elements.append(Paragraph('<b>Cipher Suite Usage:</b>', normal_style))
    if cipher_list:
        cipher_data = [['Cipher Suite', 'Count']]
        for cs, count in cipher_list:
            cipher_data.append([cs[:40], str(count)])
        cipher_table = Table(cipher_data, colWidths=[4*inch, 1*inch])
        cipher_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), DARK),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
        ]))
        elements.append(cipher_table)
    else:
        elements.append(Paragraph('No cipher data available.', normal_style))
    
    elements.append(Spacer(1, 20))
    
    key_lengths = {}
    for a in assets:
        kl = a.get('key_length')
        if kl:
            key_lengths[kl] = key_lengths.get(kl, 0) + 1
    
    elements.append(Paragraph('<b>Key Length Distribution:</b>', normal_style))
    if key_lengths:
        key_data = [['Key Length', 'Count']]
        for kl in sorted(key_lengths.keys()):
            key_data.append([str(kl), str(key_lengths[kl])])
        key_table = Table(key_data, colWidths=[2*inch, 1*inch])
        key_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), DARK),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        elements.append(key_table)
    
    elements.append(PageBreak())
    
    elements.append(Paragraph('PQC Posture Assessment', heading_style))
    elements.append(Spacer(1, 10))
    
    elements.append(Paragraph('<b>Per Asset PQC Status:</b>', normal_style))
    if assets:
        posture_data = [['Asset', 'TLS Version', 'PQC Score', 'Risk', 'Recommendation']]
        for a in assets[:25]:
            rec = a.get('recommendation') or 'None'
            posture_data.append([
                (a.get('subdomain') or '-')[:20],
                a.get('tls_version') or '-',
                str(a.get('pqc_score') or 0),
                a.get('risk_level') or '-',
                rec[:30]
            ])
        posture_table = Table(posture_data, colWidths=[1.5*inch, 0.8*inch, 0.7*inch, 0.6*inch, 1.8*inch])
        posture_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), DARK),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
        ]))
        elements.append(posture_table)
    
    elements.append(Spacer(1, 20))
    
    elements.append(Paragraph('<b>Recommendations:</b>', normal_style))
    recs = ['Upgrade to TLS 1.3 where possible', 'Use AES-GCM cipher suites', 'Implement PQC hybrid algorithms', 'Regular certificate rotation', 'Monitor cryptographic standards']
    for i, rec in enumerate(recs, 1):
        elements.append(Paragraph(f'{i}. {rec}', normal_style))
    
    elements.append(PageBreak())
    
    elements.append(Paragraph('Cyber Rating', heading_style))
    elements.append(Spacer(1, 10))
    
    elements.append(Paragraph(f'<b>Overall Score: {avg_score}/1000</b>', ParagraphStyle('ScoreBig', fontSize=20, alignment=TA_CENTER, textColor=score_color)))
    elements.append(Paragraph(f'<b>Status: {overall_status}</b>', ParagraphStyle('StatusBig', fontSize=14, alignment=TA_CENTER)))
    elements.append(Spacer(1, 20))
    
    tier_data = [
        ['Tier', 'Score Range', 'Criteria', 'Your Assets'],
        ['Maximum', '1000', 'Full PQC compliance', '0'],
        ['Elite-PQC', '>700', 'TLS 1.3, strong ciphers', str(elite)],
        ['Standard', '400-700', 'TLS 1.2, mostly strong', str(standard)],
        ['Legacy', '100-400', 'TLS 1.0/1.1, weak ciphers', str(legacy)],
        ['Critical', '<100', 'RC4, MD5, obsolete', str(critical)],
    ]
    tier_table = Table(tier_data, colWidths=[1.2*inch, 1*inch, 2.2*inch, 0.8*inch])
    tier_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), DARK),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
    ]))
    elements.append(tier_table)
    
    elements.append(Spacer(1, 20))
    
    elements.append(Paragraph('<b>Per Asset Scores:</b>', normal_style))
    sorted_assets = sorted(assets, key=lambda x: x.get('pqc_score') or 0)
    if sorted_assets:
        score_data = [['Asset', 'Score', 'Status']]
        for a in sorted_assets[:20]:
            score_data.append([
                (a.get('subdomain') or '-')[:30],
                str(a.get('pqc_score') or 0),
                a.get('pqc_status') or '-'
            ])
        score_table = Table(score_data, colWidths=[3.5*inch, 0.8*inch, 1*inch])
        score_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), DARK),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
        ]))
        elements.append(score_table)
    
    elements.append(Spacer(1, 40))
    elements.append(Paragraph(f'<i>Report generated by KAVACH - Quantum Security Monitor on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</i>', 
                              ParagraphStyle('Footer', fontSize=8, alignment=TA_CENTER, textColor=colors.grey)))
    
    doc.build(elements)
    buffer.seek(0)
    
    return send_file(
        buffer,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=f'KAVACH_Report_{domain_name}.pdf'
    )

@app.route('/api/discover', methods=['POST'])
def api_discover():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    domain_name = data.get('domain')
    
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute('SELECT id FROM domains WHERE domain_name = ? AND user_id = ?', (domain_name, session['user_id']))
    existing_domain = cursor.fetchone()
    
    is_existing = existing_domain is not None
    if is_existing:
        domain_id = existing_domain['id']
    else:
        cursor.execute(
            'INSERT INTO domains (user_id, domain_name) VALUES (?, ?)',
            (session['user_id'], domain_name)
        )
        db.commit()
        domain_id = cursor.lastrowid
    
    cursor.execute('UPDATE domains SET last_discovered = CURRENT_TIMESTAMP WHERE id = ?', (domain_id,))
    db.commit()
    
    discovered_subdomains = get_subdomains(domain_name)
    
    subdomain_list = []
    for sub in discovered_subdomains:
        cursor.execute('SELECT id FROM subdomains WHERE domain_id = ? AND subdomain = ?', (domain_id, sub))
        existing_sub = cursor.fetchone()
        
        if existing_sub:
            cursor.execute('UPDATE subdomains SET last_seen = CURRENT_TIMESTAMP WHERE id = ?', (existing_sub['id'],))
        else:
            cursor.execute('INSERT INTO subdomains (domain_id, subdomain) VALUES (?, ?)', (domain_id, sub))
        db.commit()
        
        cursor.execute('SELECT id, scanned_at FROM assets WHERE domain_id = ? AND subdomain = ?', (domain_id, sub))
        asset = cursor.fetchone()
        already_scanned = asset is not None and asset['id'] is not None
        
        subdomain_list.append({
            'subdomain': sub,
            'ip': None,
            'already_scanned': already_scanned,
            'last_scanned': asset['scanned_at'] if asset and asset['scanned_at'] else None
        })
    
    db.close()
    
    return jsonify({
        'domain_id': domain_id,
        'domain_name': domain_name,
        'is_existing': is_existing,
        'subdomains': subdomain_list
    })

def run_scan(domain_id, subdomains, domain_name):
    db = get_db()
    cursor = db.cursor()
    
    for subdomain in subdomains:
        result = scan_subdomain(subdomain)
        
        if result.get('scan_error'):
            pqc_result = {
                'score': 0,
                'status': 'Error',
                'risk_level': 'unknown',
                'color': 'gray',
                'recommendation': result.get('scan_error'),
                'tls_score': 0,
                'cipher_score': 0,
                'key_score': 0,
                'pqc_score': 0
            }
        else:
            pqc_result = check_pqc(
                result.get('tls_version'),
                result.get('cipher_suite'),
                result.get('key_length')
            )
        
        cursor.execute('SELECT scan_count FROM assets WHERE domain_id = ? AND subdomain = ?', (domain_id, subdomain))
        existing = cursor.fetchone()
        current_count = existing['scan_count'] + 1 if existing else 1
        
        cursor.execute('''
            INSERT OR REPLACE INTO assets (
                domain_id, subdomain, ip_address, tls_version, cipher_suite,
                key_length, cert_expiry, cert_authority, cert_common_name,
                cert_fingerprint, server_software, pqc_status, pqc_score,
                risk_level, scan_error, scanned_at, last_scanned, scan_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?)
        ''', (
            domain_id,
            subdomain,
            None,
            result.get('tls_version'),
            result.get('cipher_suite'),
            result.get('key_length'),
            result.get('cert_expiry'),
            result.get('cert_authority'),
            result.get('cert_common_name'),
            result.get('cert_fingerprint'),
            None,
            pqc_result.get('status'),
            pqc_result.get('score'),
            pqc_result.get('risk_level'),
            result.get('scan_error'),
            current_count
        ))
        db.commit()
    
    cursor.execute('UPDATE domains SET last_scanned = CURRENT_TIMESTAMP WHERE id = ?', (domain_id,))
    db.commit()
    db.close()

@app.route('/api/scan', methods=['POST'])
def api_scan():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    domain_id = data.get('domain_id')
    selected_subdomains = data.get('selected_subdomains', [])
    
    if not domain_id:
        return jsonify({'error': 'domain_id required'}), 400
    
    if not verify_domain_ownership(domain_id, session['user_id']):
        return jsonify({'error': 'unauthorized'}), 401
    
    thread = threading.Thread(target=run_scan, args=(domain_id, selected_subdomains, None))
    thread.start()
    
    return jsonify({'domain_id': domain_id, 'status': 'scanning'})

@app.route('/api/scan/progress/<domain_id>', methods=['GET'])
def api_scan_progress(domain_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    if not verify_domain_ownership(domain_id, session['user_id']):
        return jsonify({'error': 'unauthorized'}), 401
    
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute('SELECT COUNT(*) as count FROM assets WHERE domain_id = ?', (domain_id,))
    completed = cursor.fetchone()['count']
    
    cursor.execute('SELECT last_scanned FROM domains WHERE id = ?', (domain_id,))
    domain = cursor.fetchone()
    
    db.close()
    
    if domain:
        is_scanning = domain['last_scanned'] is None or (datetime.now() - datetime.strptime(domain['last_scanned'], '%Y-%m-%d %H:%M:%S')).seconds < 60 if domain['last_scanned'] else False
        return jsonify({
            'completed': completed,
            'total': completed,
            'status': 'scanning' if is_scanning else 'completed'
        })
    
    return jsonify({'error': 'Domain not found'}), 404

@app.route('/api/my-domains', methods=['GET'])
def api_my_domains():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        SELECT d.*, 
               (SELECT COUNT(*) FROM assets WHERE domain_id = d.id) as asset_count,
               (SELECT COUNT(*) FROM subdomains WHERE domain_id = d.id) as subdomain_count
        FROM domains d 
        WHERE d.user_id = ? 
        ORDER BY d.added_at DESC
    ''', (session['user_id'],))
    domains = [dict(row) for row in cursor.fetchall()]
    db.close()
    
    return jsonify(domains)

@app.route('/api/domain/<int:domain_id>/subdomains', methods=['GET'])
def api_domain_subdomains(domain_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    if not verify_domain_ownership(domain_id, session['user_id']):
        return jsonify({'error': 'unauthorized'}), 401
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        SELECT s.*, 
               a.scanned_at as last_scanned,
               a.pqc_score,
               a.pqc_status,
               a.tls_version,
               a.cipher_suite,
               a.risk_level,
               a.scan_error
        FROM subdomains s
        LEFT JOIN assets a ON s.subdomain = a.subdomain AND s.domain_id = a.domain_id
        WHERE s.domain_id = ?
        ORDER BY s.last_seen DESC
    ''', (domain_id,))
    subdomains = [dict(row) for row in cursor.fetchall()]
    db.close()
    
    return jsonify(subdomains)

def verify_domain_ownership(domain_id, user_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT id FROM domains WHERE id = ? AND user_id = ?', (domain_id, user_id))
    result = cursor.fetchone()
    db.close()
    return result is not None

@app.route('/api/dashboard', methods=['GET'])
def api_dashboard():
    if 'user_id' not in session:
        return jsonify({'error': 'unauthorized'}), 401
    
    user_id = session['user_id']
    domain_id = request.args.get('domain_id')
    
    if domain_id and domain_id != 'all':
        domain_id = int(domain_id)
        if not verify_domain_ownership(domain_id, user_id):
            return jsonify({'error': 'unauthorized'}), 401
        domain_filter = " AND assets.domain_id = ?"
        domain_params = (user_id, domain_id)
        single_domain = True
    else:
        domain_filter = ""
        domain_params = (user_id,)
        single_domain = False
    
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute(f'''
        SELECT COUNT(*) as count FROM assets
        JOIN domains ON assets.domain_id = domains.id
        WHERE domains.user_id = ?{domain_filter}
    ''', domain_params)
    total_assets = cursor.fetchone()['count']
    
    cursor.execute(f'''
        SELECT COUNT(*) as count FROM assets
        JOIN domains ON assets.domain_id = domains.id
        WHERE domains.user_id = ?{domain_filter}
        AND assets.risk_level IN ('high', 'critical')
    ''', domain_params)
    high_risk = cursor.fetchone()['count']
    
    cursor.execute(f'''
        SELECT COUNT(*) as count FROM assets
        JOIN domains ON assets.domain_id = domains.id
        WHERE domains.user_id = ?{domain_filter}
        AND assets.risk_level = 'critical'
    ''', domain_params)
    critical = cursor.fetchone()['count']
    
    cursor.execute(f'''
        SELECT COUNT(*) as count FROM assets
        JOIN domains ON assets.domain_id = domains.id
        WHERE domains.user_id = ?{domain_filter}
        AND assets.cert_expiry IS NOT NULL
        AND date(assets.cert_expiry) <= date('now', '+30 days')
    ''', domain_params)
    expiring_certs = cursor.fetchone()['count']
    
    if single_domain:
        cursor.execute('SELECT COUNT(*) as count FROM domains WHERE user_id = ? AND id = ?', (user_id, domain_id))
    else:
        cursor.execute('SELECT COUNT(*) as count FROM domains WHERE user_id = ?', (user_id,))
    total_domains = cursor.fetchone()['count']
    
    cursor.execute(f'''
        SELECT risk_level, COUNT(*) as count
        FROM assets
        JOIN domains ON assets.domain_id = domains.id
        WHERE domains.user_id = ?{domain_filter}
        GROUP BY risk_level
    ''', domain_params)
    risk_distribution = [dict(row) for row in cursor.fetchall()]
    
    cursor.execute(f'''
        SELECT cipher_suite, COUNT(*) as count
        FROM assets
        JOIN domains ON assets.domain_id = domains.id
        WHERE domains.user_id = ?{domain_filter}
        AND cipher_suite IS NOT NULL
        GROUP BY cipher_suite
        ORDER BY count DESC
        LIMIT 5
    ''', domain_params)
    cipher_usage = [dict(row) for row in cursor.fetchall()]
    
    cursor.execute(f'''
        SELECT tls_version, COUNT(*) as count
        FROM assets
        JOIN domains ON assets.domain_id = domains.id
        WHERE domains.user_id = ?{domain_filter}
        AND tls_version IS NOT NULL
        GROUP BY tls_version
    ''', domain_params)
    tls_distribution = [dict(row) for row in cursor.fetchall()]
    
    cursor.execute(f'''
        SELECT pqc_status, COUNT(*) as count
        FROM assets
        JOIN domains ON assets.domain_id = domains.id
        WHERE domains.user_id = ?{domain_filter}
        GROUP BY pqc_status
    ''', domain_params)
    pqc_distribution = [dict(row) for row in cursor.fetchall()]
    
    cursor.execute(f'''
        SELECT assets.*, domains.domain_name
        FROM assets
        JOIN domains ON assets.domain_id = domains.id
        WHERE domains.user_id = ?{domain_filter}
        ORDER BY assets.scanned_at DESC
        LIMIT 10
    ''', domain_params)
    recent_assets = [dict(row) for row in cursor.fetchall()]
    
    db.close()
    
    return jsonify({
        'total_assets': total_assets,
        'high_risk': high_risk,
        'critical': critical,
        'expiring_certs': expiring_certs,
        'total_domains': total_domains,
        'risk_distribution': risk_distribution,
        'cipher_usage': cipher_usage,
        'tls_distribution': tls_distribution,
        'pqc_distribution': pqc_distribution,
        'recent_assets': recent_assets
    })

@app.route('/api/discovery/domains/<int:domain_id>', methods=['GET'])
def api_discovery_domains(domain_id):
    if 'user_id' not in session:
        return jsonify({'error': 'unauthorized'}), 401
    
    if not verify_domain_ownership(domain_id, session['user_id']):
        return jsonify({'error': 'unauthorized'}), 401
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM assets WHERE domain_id = ?', (domain_id,))
    assets = [dict(row) for row in cursor.fetchall()]
    db.close()
    
    return jsonify(assets)

@app.route('/api/discovery/ssl/<int:domain_id>', methods=['GET'])
def api_discovery_ssl(domain_id):
    if 'user_id' not in session:
        return jsonify({'error': 'unauthorized'}), 401
    
    if not verify_domain_ownership(domain_id, session['user_id']):
        return jsonify({'error': 'unauthorized'}), 401
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        SELECT subdomain, cert_common_name, cert_fingerprint,
        cert_authority, cert_expiry, scanned_at
        FROM assets WHERE domain_id = ?
        AND cert_fingerprint IS NOT NULL
    ''', (domain_id,))
    assets = [dict(row) for row in cursor.fetchall()]
    db.close()
    
    return jsonify(assets)

@app.route('/api/discovery/ips/<int:domain_id>', methods=['GET'])
def api_discovery_ips(domain_id):
    if 'user_id' not in session:
        return jsonify({'error': 'unauthorized'}), 401
    
    if not verify_domain_ownership(domain_id, session['user_id']):
        return jsonify({'error': 'unauthorized'}), 401
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM ip_records WHERE domain_id = ?', (domain_id,))
    records = [dict(row) for row in cursor.fetchall()]
    db.close()
    
    return jsonify(records)

@app.route('/api/discovery/software/<int:domain_id>', methods=['GET'])
def api_discovery_software(domain_id):
    if 'user_id' not in session:
        return jsonify({'error': 'unauthorized'}), 401
    
    if not verify_domain_ownership(domain_id, session['user_id']):
        return jsonify({'error': 'unauthorized'}), 401
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        SELECT subdomain, server_software, ip_address, scanned_at
        FROM assets WHERE domain_id = ?
        AND server_software IS NOT NULL
        AND server_software != 'Unreachable'
    ''', (domain_id,))
    assets = [dict(row) for row in cursor.fetchall()]
    db.close()
    
    return jsonify(assets)

@app.route('/api/cbom', methods=['GET'])
def api_cbom_all():
    if 'user_id' not in session:
        return jsonify({'error': 'unauthorized'}), 401
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        SELECT assets.* FROM assets
        JOIN domains ON assets.domain_id = domains.id
        WHERE domains.user_id = ?
    ''', (session['user_id'],))
    assets = [dict(row) for row in cursor.fetchall()]
    
    return jsonify(aggregate_cbom(assets))

@app.route('/api/cbom/<int:domain_id>', methods=['GET'])
def api_cbom(domain_id):
    if 'user_id' not in session:
        return jsonify({'error': 'unauthorized'}), 401
    
    if not verify_domain_ownership(domain_id, session['user_id']):
        return jsonify({'error': 'unauthorized'}), 401
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM assets WHERE domain_id = ?', (domain_id,))
    assets = [dict(row) for row in cursor.fetchall()]
    
    return jsonify(aggregate_cbom(assets))

def aggregate_cbom(assets):
    total_assets = len(assets)
    weak_crypto = sum(1 for a in assets if a.get('risk_level') in ('high', 'critical'))
    
    from datetime import datetime
    today = datetime.now().date()
    cert_issues = 0
    for a in assets:
        if a.get('cert_expiry'):
            try:
                expiry_date = datetime.strptime(a['cert_expiry'].split()[0], '%Y-%m-%d').date()
                if expiry_date < today:
                    cert_issues += 1
            except:
                pass
    
    key_distribution = {}
    for a in assets:
        kl = a.get('key_length')
        if kl:
            key_distribution[kl] = key_distribution.get(kl, 0) + 1
    
    cipher_usage = {}
    for a in assets:
        cs = a.get('cipher_suite')
        if cs:
            cipher_usage[cs] = cipher_usage.get(cs, 0) + 1
    cipher_usage_list = [{'cipher_suite': k, 'count': v} for k, v in sorted(cipher_usage.items(), key=lambda x: x[1], reverse=True)]
    
    ca_distribution = {}
    for a in assets:
        ca = a.get('cert_authority')
        if ca:
            ca_distribution[ca] = ca_distribution.get(ca, 0) + 1
    ca_distribution_list = [{'certificate_authority': k, 'count': v} for k, v in sorted(ca_distribution.items(), key=lambda x: x[1], reverse=True)]
    
    tls_distribution = {}
    for a in assets:
        tls = a.get('tls_version')
        if tls:
            tls_distribution[tls] = tls_distribution.get(tls, 0) + 1
    tls_distribution_list = [{'tls_version': k, 'count': v} for k, v in tls_distribution.items()]
    
    assets_list = [
        {
            'subdomain': a.get('subdomain'),
            'key_length': a.get('key_length'),
            'cipher_suite': a.get('cipher_suite'),
            'certificate_authority': a.get('cert_authority'),
            'cert_issues': 1 if a.get('cert_expiry') and datetime.strptime(a.get('cert_expiry').split()[0], '%Y-%m-%d').date() < today else 0
        }
        for a in assets
    ]
    
    return {
        'total_assets': total_assets,
        'weak_crypto': weak_crypto,
        'cert_issues': cert_issues,
        'key_lengths': key_distribution,
        'cipher_suites': cipher_usage_list,
        'certificate_authorities': ca_distribution_list,
        'tls_versions': tls_distribution_list,
        'assets': assets_list
    }

@app.route('/api/posture', methods=['GET'])
def api_posture_all():
    if 'user_id' not in session:
        return jsonify({'error': 'unauthorized'}), 401
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        SELECT assets.*, domains.domain_name FROM assets
        JOIN domains ON assets.domain_id = domains.id
        WHERE domains.user_id = ?
    ''', (session['user_id'],))
    assets = [dict(row) for row in cursor.fetchall()]
    
    return jsonify(aggregate_posture(assets))

@app.route('/api/posture/<int:domain_id>', methods=['GET'])
def api_posture(domain_id):
    if 'user_id' not in session:
        return jsonify({'error': 'unauthorized'}), 401
    
    if not verify_domain_ownership(domain_id, session['user_id']):
        return jsonify({'error': 'unauthorized'}), 401
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        SELECT assets.*, domains.domain_name FROM assets
        JOIN domains ON assets.domain_id = domains.id
        WHERE assets.domain_id = ?
    ''', (domain_id,))
    assets = [dict(row) for row in cursor.fetchall()]
    
    return jsonify(aggregate_posture(assets))

def aggregate_posture(assets):
    total = len(assets)
    elite_count = sum(1 for a in assets if a.get('pqc_status') == 'Elite-PQC')
    standard_count = sum(1 for a in assets if a.get('pqc_status') == 'Standard')
    legacy_count = sum(1 for a in assets if a.get('pqc_status') == 'Legacy')
    critical_count = sum(1 for a in assets if a.get('pqc_status') == 'Critical')
    
    elite_pct = round(elite_count / total * 100, 2) if total > 0 else 0
    standard_pct = round(standard_count / total * 100, 2) if total > 0 else 0
    legacy_pct = round(legacy_count / total * 100, 2) if total > 0 else 0
    critical_pct = round(critical_count / total * 100, 2) if total > 0 else 0
    
    posture_assets = [
        {
            'subdomain': a.get('subdomain'),
            'domain_name': a.get('domain_name'),
            'pqc_status': a.get('pqc_status'),
            'pqc_score': a.get('pqc_score'),
            'risk_level': a.get('risk_level'),
            'tls_version': a.get('tls_version'),
            'cipher_suite': a.get('cipher_suite'),
            'recommendation': a.get('recommendation') if a.get('recommendation') else ''
        }
        for a in assets
    ]
    
    recommendations = []
    risk_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    unique_recs = {}
    for a in assets:
        rec = a.get('recommendation')
        if rec and rec not in unique_recs:
            risk = a.get('risk_level', 'low')
            unique_recs[rec] = risk
    
    for rec, risk in sorted(unique_recs.items(), key=lambda x: risk_order.get(x[1], 99)):
        recommendations.append(rec)
    
    return {
        'elite_count': elite_count,
        'standard_count': standard_count,
        'legacy_count': legacy_count,
        'critical_count': critical_count,
        'total': total,
        'elite_pct': elite_pct,
        'standard_pct': standard_pct,
        'legacy_pct': legacy_pct,
        'critical_pct': critical_pct,
        'assets': posture_assets,
        'recommendations': recommendations
    }

@app.route('/api/rating', methods=['GET'])
def api_rating_all():
    if 'user_id' not in session:
        return jsonify({'error': 'unauthorized'}), 401
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        SELECT assets.*, domains.domain_name FROM assets
        JOIN domains ON assets.domain_id = domains.id
        WHERE domains.user_id = ? AND assets.scan_error IS NULL
    ''', (session['user_id'],))
    assets = [dict(row) for row in cursor.fetchall()]
    db.close()
    
    total_assets = len(assets)
    
    if total_assets == 0:
        return jsonify({
            'overall_score': 0,
            'overall_status': 'No Data',
            'total_assets': 0,
            'per_asset': [],
            'elite_count': 0,
            'standard_count': 0,
            'legacy_count': 0,
            'critical_count': 0
        })
    
    scores = [a.get('pqc_score', 0) or 0 for a in assets]
    avg_score = round(sum(scores) / len(scores))
    
    if avg_score > 700:
        overall_status = 'Elite-PQC'
    elif avg_score >= 400:
        overall_status = 'Standard'
    elif avg_score >= 100:
        overall_status = 'Legacy'
    else:
        overall_status = 'Critical'
    
    per_asset = [
        {
            'subdomain': a.get('subdomain'),
            'domain_name': a.get('domain_name'),
            'pqc_score': a.get('pqc_score'),
            'pqc_status': a.get('pqc_status'),
            'tls_version': a.get('tls_version'),
            'cipher_suite': a.get('cipher_suite')
        }
        for a in assets
    ]
    per_asset.sort(key=lambda x: x['pqc_score'] or 0)
    
    elite_count = sum(1 for a in assets if a.get('pqc_status') == 'Elite-PQC')
    standard_count = sum(1 for a in assets if a.get('pqc_status') == 'Standard')
    legacy_count = sum(1 for a in assets if a.get('pqc_status') == 'Legacy')
    critical_count = sum(1 for a in assets if a.get('pqc_status') == 'Critical')
    
    return jsonify({
        'overall_score': avg_score,
        'overall_status': overall_status,
        'total_assets': total_assets,
        'per_asset': per_asset,
        'elite_count': elite_count,
        'standard_count': standard_count,
        'legacy_count': legacy_count,
        'critical_count': critical_count
    })

@app.route('/api/rating/<int:domain_id>', methods=['GET'])
def api_rating(domain_id):
    if 'user_id' not in session:
        return jsonify({'error': 'unauthorized'}), 401
    
    if not verify_domain_ownership(domain_id, session['user_id']):
        return jsonify({'error': 'unauthorized'}), 401
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        SELECT * FROM assets WHERE domain_id = ? AND scan_error IS NULL
    ''', (domain_id,))
    assets = [dict(row) for row in cursor.fetchall()]
    db.close()
    
    total_assets = len(assets)
    
    if total_assets == 0:
        return jsonify({
            'overall_score': 0,
            'overall_status': 'No Data',
            'total_assets': 0,
            'per_asset': [],
            'elite_count': 0,
            'standard_count': 0,
            'legacy_count': 0,
            'critical_count': 0
        })
    
    scores = [a.get('pqc_score', 0) or 0 for a in assets]
    avg_score = round(sum(scores) / len(scores))
    
    if avg_score > 700:
        overall_status = 'Elite-PQC'
    elif avg_score >= 400:
        overall_status = 'Standard'
    elif avg_score >= 100:
        overall_status = 'Legacy'
    else:
        overall_status = 'Critical'
    
    per_asset = [
        {
            'subdomain': a.get('subdomain'),
            'pqc_score': a.get('pqc_score'),
            'pqc_status': a.get('pqc_status'),
            'tls_version': a.get('tls_version'),
            'cipher_suite': a.get('cipher_suite')
        }
        for a in assets
    ]
    per_asset.sort(key=lambda x: x['pqc_score'] or 0)
    
    elite_count = sum(1 for a in assets if a.get('pqc_status') == 'Elite-PQC')
    standard_count = sum(1 for a in assets if a.get('pqc_status') == 'Standard')
    legacy_count = sum(1 for a in assets if a.get('pqc_status') == 'Legacy')
    critical_count = sum(1 for a in assets if a.get('pqc_status') == 'Critical')
    
    return jsonify({
        'overall_score': avg_score,
        'overall_status': overall_status,
        'total_assets': total_assets,
        'per_asset': per_asset,
        'elite_count': elite_count,
        'standard_count': standard_count,
        'legacy_count': legacy_count,
        'critical_count': critical_count
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
