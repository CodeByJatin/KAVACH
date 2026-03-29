import sqlite3
import os

DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'kavach.db')

def get_db():
    db = sqlite3.connect(DATABASE_PATH)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            domain_name TEXT NOT NULL,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_discovered TIMESTAMP,
            last_scanned TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE(user_id, domain_name)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS subdomains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain_id INTEGER NOT NULL,
            subdomain TEXT NOT NULL,
            ip_address TEXT,
            server_software TEXT,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (domain_id) REFERENCES domains(id),
            UNIQUE(domain_id, subdomain)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain_id INTEGER NOT NULL,
            subdomain TEXT NOT NULL,
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
            scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_scanned TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            scan_count INTEGER DEFAULT 0,
            FOREIGN KEY (domain_id) REFERENCES domains(id),
            UNIQUE(domain_id, subdomain)
        )
    ''')
    
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

if __name__ == '__main__':
    init_db()
    print("Database initialized successfully!")
