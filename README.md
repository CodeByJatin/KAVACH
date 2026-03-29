# KAVACH - Quantum Security Monitoring Platform

A multi-user web-based quantum security monitoring platform for banks that discovers subdomains via certificate transparency logs, performs TLS analysis, checks cryptography against NIST PQC standards, and provides comprehensive security reports.

## Features

- **Multi-user Authentication**: Secure user registration and login with password hashing
- **Domain Management**: Add and manage multiple bank domains
- **Subdomain Discovery**: Automatic discovery via crt.sh certificate transparency API
- **TLS Scanning**: Comprehensive TLS/SSL analysis of all subdomains
- **PQC Assessment**: Evaluate cryptography against NIST post-quantum cryptography standards
- **Scoring System**: 0-1000 scoring with Elite/Standard/Legacy/Critical ratings
- **6 Modules**: Dashboard, Discovery, CBOM, Posture, Rating, and Reporting
- **PDF Reports**: Generate downloadable comprehensive security reports
- **Real-time Scanning**: Progress tracking during scans

## Tech Stack

- **Backend**: Python 3.10+, Flask 3.0
- **Database**: SQLite (no setup required)
- **Frontend**: HTML5, Tailwind CSS (via CDN), Chart.js
- **TLS Scanning**: Python ssl module
- **Report Generation**: ReportLab
- **Discovery**: crt.sh public API

## Installation

1. Clone or navigate to the project directory:
```bash
cd Kavach
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python app.py
```

4. Open your browser and navigate to:
```
http://localhost:5000
```

## Usage

### Registration & Login

1. Navigate to `http://localhost:5000/register`
2. Create a new account with your name, email, and password
3. You'll be automatically logged in and redirected to the dashboard

### Adding a Domain

1. Click "Add Domain" in the sidebar
2. Enter a bank domain (e.g., `pnb.bank.in`)
3. Click "Discover Subdomains"
4. The system will query crt.sh and display all discovered subdomains
5. Select the subdomains you want to scan deeply
6. Click "Start Deep Scan"
7. Monitor the progress as each subdomain is scanned

### Dashboard

View comprehensive statistics:
- Total domains and assets
- Average PQC score
- Critical asset counts
- PQC status distribution charts
- List of all your domains with their status

### Discovery Module

View detailed asset information with 4 tabs:
- **Domains**: All discovered subdomains with TLS details
- **SSL Certificates**: Certificate information and expiry dates
- **IP Addresses**: IP address distribution
- **Server Software**: Web server software detection

### CBOM (Cryptographic Bill of Materials)

View cryptographic inventory:
- Cipher suite distribution
- Key length distribution
- TLS version distribution
- Certificate authority breakdown
- Weak instance identification
- Security recommendations

### Posture Module

Assess quantum security posture:
- Per-asset quantum safety status
- Detailed recommendations for each asset
- Risk level assessment
- Improvement suggestions

### Rating Module

View overall cyber ratings:
- Domain-wide average score (0-1000)
- Rating classification (Elite-PQC, Standard, Legacy, Critical)
- Score breakdown by category
- Individual asset ratings

### Reporting

Generate comprehensive PDF reports:
1. Select a domain
2. Click "Generate PDF Report"
3. Download includes:
   - Asset inventory
   - TLS version analysis
   - Cipher suite information
   - PQC assessment results
   - Security recommendations
   - CBOM summary

## Scoring System

Each asset is scored 0-1000 based on:

### TLS Version (250 points)
- TLS 1.3 → 250 pts
- TLS 1.2 → 150 pts
- TLS 1.1 → 50 pts
- TLS 1.0/SSL → 0 pts

### Cipher Suite (250 points)
- AES-256-GCM, ChaCha20-Poly1305 → 250 pts
- AES-128-GCM → 200 pts
- AES-256-CBC → 100 pts
- 3DES, RC4, DES → 0 pts

### Key Length (250 points)
- ≥4096 bits → 250 pts
- ≥3072 bits → 200 pts
- ≥2048 bits → 175 pts
- ≥1024 bits → 75 pts
- <1024 bits → 0 pts

### PQC Compliance (250 points)
- ML-KEM/Hybrid PQC → 250 pts
- TLS 1.3 minimum → 100 pts
- TLS 1.2 only → 50 pts
- Weak cipher → 0 pts

### Overall Rating
- **Elite-PQC** (>700): Excellent quantum-safe configuration
- **Standard** (400-700): Good but needs improvement
- **Legacy** (100-400): Outdated configuration
- **Critical** (<100): Critical vulnerabilities detected

## Project Structure

```
KAVACH/
├── app.py                    # Main Flask application
├── database.py               # Database schema and helper functions
├── requirements.txt          # Python dependencies
├── scanner/
│   ├── __init__.py
│   ├── discovery.py          # Subdomain discovery via crt.sh
│   ├── tls_scanner.py        # TLS/SSL analysis
│   ├── pqc_checker.py        # PQC scoring logic
│   └── cbom_builder.py       # Cryptographic Bill of Materials
├── static/
│   ├── css/
│   │   └── style.css         # Custom styles
│   └── js/
│       ├── main.js           # Core JavaScript functions
│       └── charts.js         # Chart.js utilities
└── templates/
    ├── login.html            # Login page
    ├── register.html         # Registration page
    ├── index.html            # Main dashboard shell
    └── pages/
        ├── home.html         # Dashboard page
        ├── add_domain.html   # Add domain page
        ├── discovery.html     # Discovery module
        ├── cbom.html         # CBOM module
        ├── posture.html      # Posture module
        ├── rating.html       # Rating module
        └── reporting.html    # Reporting module
```

## Security Features

- **User Isolation**: Each user's data is completely private
- **Password Hashing**: Werkzeug's secure password hashing
- **Session Management**: Flask session-based authentication
- **Input Validation**: Server-side validation of all inputs
- **Error Handling**: Graceful error handling for network issues

## API Endpoints

### Authentication
- `POST /api/register` - Create new account
- `POST /api/login` - Login
- `POST /api/logout` - Logout
- `GET /api/me` - Get current user info

### Scanning
- `POST /api/discover` - Discover subdomains
- `POST /api/scan` - Deep scan selected subdomains
- `GET /api/scan/progress/<id>` - Get scan progress

### Dashboard
- `GET /api/dashboard` - Get dashboard statistics
- `GET /api/my-domains` - List user's domains
- `DELETE /api/domains/<id>` - Delete a domain

### Module Data
- `GET /api/discovery/domains/<id>` - Domain discovery data
- `GET /api/discovery/ssl/<id>` - SSL certificate data
- `GET /api/discovery/ips/<id>` - IP address data
- `GET /api/discovery/software/<id>` - Server software data
- `GET /api/cbom/<id>` - CBOM data
- `GET /api/posture/<id>` - PQC posture data
- `GET /api/rating/<id>` - Cyber rating data

### Reporting
- `GET /api/report/<id>` - Generate and download PDF report

## Troubleshooting

### Application Won't Start
- Ensure all dependencies are installed: `pip install -r requirements.txt`
- Check if port 5000 is available
- Verify Python version (3.10+ required)

### Discovery Fails
- Check internet connectivity
- Verify crt.sh API is accessible
- Some domains may have no certificates in transparency logs

### Scan Errors
- Subdomain may be unreachable
- Firewall may be blocking connections
- Check individual subdomain manually with browser

### PDF Report Issues
- Ensure ReportLab is installed
- Check write permissions for downloads
- Some browsers may block automatic downloads

## Development

The application runs in debug mode by default. To disable debug mode, modify the last line of `app.py`:

```python
if __name__ == '__main__':
    db.init_db()
    app.run(debug=False, host='0.0.0.0', port=5000)
```

## License

This project is for educational and security assessment purposes.

## Support

For issues or questions, please refer to the project documentation or contact the development team.
