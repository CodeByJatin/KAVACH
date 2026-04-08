from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String, nullable=False)
    email = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    totp_secret = db.Column(db.String)
    mfa_enabled = db.Column(db.Integer, default=0)
    domains = db.relationship('Domain', backref='user', lazy=True)

class Domain(db.Model):
    __tablename__ = 'domains'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    domain_name = db.Column(db.String, nullable=False)
    added_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_scanned = db.Column(db.DateTime)
    status = db.Column(db.String, default='pending')
    discovery_status = db.Column(db.String, default='pending')
    assets = db.relationship('Asset', backref='domain', lazy=True, cascade='all, delete-orphan')
    ip_records = db.relationship('IPRecord', backref='domain', lazy=True, cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'domain_name': self.domain_name,
            'added_at': self.added_at.isoformat() if self.added_at else None,
            'last_scanned': self.last_scanned.isoformat() if self.last_scanned else None,
            'status': self.status,
            'discovery_status': self.discovery_status
        }

class Asset(db.Model):
    __tablename__ = 'assets'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    domain_id = db.Column(db.Integer, db.ForeignKey('domains.id'), nullable=False)
    subdomain = db.Column(db.String)
    ip_address = db.Column(db.String)
    tls_version = db.Column(db.String)
    cipher_suite = db.Column(db.String)
    key_length = db.Column(db.Integer)
    key_type = db.Column(db.String)
    cert_expiry = db.Column(db.String)
    cert_authority = db.Column(db.String)
    cert_common_name = db.Column(db.String)
    cert_fingerprint = db.Column(db.String)
    server_software = db.Column(db.String)
    pqc_status = db.Column(db.String)
    pqc_score = db.Column(db.Integer)
    risk_level = db.Column(db.String)
    scan_error = db.Column(db.String)
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    country = db.Column(db.String)
    city = db.Column(db.String)
    scanned_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'domain_id': self.domain_id,
            'subdomain': self.subdomain,
            'ip_address': self.ip_address,
            'tls_version': self.tls_version,
            'cipher_suite': self.cipher_suite,
            'key_length': self.key_length,
            'key_type': self.key_type,
            'cert_expiry': self.cert_expiry,
            'cert_authority': self.cert_authority,
            'cert_common_name': self.cert_common_name,
            'cert_fingerprint': self.cert_fingerprint,
            'server_software': self.server_software,
            'pqc_status': self.pqc_status,
            'pqc_score': self.pqc_score,
            'risk_level': self.risk_level,
            'scan_error': self.scan_error,
            'latitude': self.latitude,
            'longitude': self.longitude,
            'country': self.country,
            'city': self.city,
            'scanned_at': self.scanned_at.isoformat() if self.scanned_at else None
        }

class IPRecord(db.Model):
    __tablename__ = 'ip_records'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    domain_id = db.Column(db.Integer, db.ForeignKey('domains.id'), nullable=False)
    ip_address = db.Column(db.String)
    ports = db.Column(db.String)
    subnet = db.Column(db.String)
    asn = db.Column(db.String)
    netname = db.Column(db.String)
    location = db.Column(db.String)
    company = db.Column(db.String)

