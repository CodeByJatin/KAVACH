import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'kavach.db')

def get_db():
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    # users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # domains table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            domain_name TEXT NOT NULL,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_scanned TIMESTAMP,
            status TEXT DEFAULT 'pending',
            discovery_status TEXT DEFAULT 'pending',
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # assets table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain_id INTEGER NOT NULL,
            subdomain TEXT,
            ip_address TEXT,
            tls_version TEXT,
            cipher_suite TEXT,
            key_length INTEGER,
            cert_expiry TEXT,
            cert_authority TEXT,
            cert_common_name TEXT,
            cert_fingerprint TEXT,
            server_software TEXT,
            pqc_status TEXT,
            pqc_score INTEGER,
            risk_level TEXT,
            scan_error TEXT,
            latitude REAL,
            longitude REAL,
            country TEXT,
            city TEXT,
            scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (domain_id) REFERENCES domains(id)
        )
    ''')
    
    # Migration: add geo columns to existing databases
    for col, coltype in [('latitude', 'REAL'), ('longitude', 'REAL'), ('country', 'TEXT'), ('city', 'TEXT'), ('key_type', 'TEXT')]:
        try:
            cursor.execute(f'ALTER TABLE assets ADD COLUMN {col} {coltype}')
        except Exception:
            pass  # column already exists
    
    # Migration: add TOTP secret column for MFA
    try:
        cursor.execute('ALTER TABLE users ADD COLUMN totp_secret TEXT')
    except Exception:
        pass  # column already exists
    
    # Migration: add MFA enabled flag
    try:
        cursor.execute('ALTER TABLE users ADD COLUMN mfa_enabled INTEGER DEFAULT 0')
    except Exception:
        pass  # column already exists
    
    # ip_records table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ip_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain_id INTEGER NOT NULL,
            ip_address TEXT,
            ports TEXT,
            subnet TEXT,
            asn TEXT,
            netname TEXT,
            location TEXT,
            company TEXT,
            FOREIGN KEY (domain_id) REFERENCES domains(id)
        )
    ''')
    
    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    print("Database Initialized Successfully.")
