def check_pqc(tls_version, cipher_suite, key_length):
    tls_score = 0
    cipher_score = 0
    key_score = 0
    pqc_score = 0
    
    if tls_version == "TLS 1.3":
        tls_score = 250
    elif tls_version == "TLS 1.2":
        tls_score = 150
    elif tls_version == "TLS 1.1":
        tls_score = 50
    elif tls_version == "TLS 1.0":
        tls_score = 0
    else:
        tls_score = 0
    
    if cipher_suite:
        if "AES_256_GCM" in cipher_suite:
            cipher_score = 250
        elif "AES_128_GCM" in cipher_suite or "CHACHA20" in cipher_suite:
            cipher_score = 200
        elif "AES_256_CBC" in cipher_suite:
            cipher_score = 100
        elif "AES_128_CBC" in cipher_suite:
            cipher_score = 75
        elif "3DES" in cipher_suite or "RC4" in cipher_suite or "DES" in cipher_suite or "NULL" in cipher_suite:
            cipher_score = 0
        else:
            cipher_score = 100
    else:
        cipher_score = 0
    
    if key_length and key_length > 0:
        if key_length >= 4096:
            key_score = 250
        elif key_length >= 3072:
            key_score = 200
        elif key_length >= 2048:
            key_score = 175
        elif key_length >= 1024:
            key_score = 75
        else:
            key_score = 0
    else:
        key_score = 50
    
    if cipher_suite and ("ML_KEM" in cipher_suite or "KYBER" in cipher_suite):
        pqc_score = 250
    elif cipher_suite and "HYBRID" in cipher_suite:
        pqc_score = 175
    elif tls_version == "TLS 1.3" and cipher_score >= 200:
        pqc_score = 100
    elif tls_version == "TLS 1.2":
        pqc_score = 50
    elif cipher_suite and ("3DES" in cipher_suite or "RC4" in cipher_suite or "DES" in cipher_suite):
        pqc_score = 0
    else:
        pqc_score = 25
    
    total = tls_score + cipher_score + key_score + pqc_score
    
    if total > 700:
        status = "Elite-PQC"
        risk_level = "low"
        color = "green"
        recommendation = "Maintain current configuration. Monitor for new standards"
    elif total >= 400:
        status = "Standard"
        risk_level = "medium"
        color = "yellow"
        recommendation = "Consider upgrading to TLS 1.3. Implement PQC hybrid mode"
    elif total >= 100:
        status = "Legacy"
        risk_level = "high"
        color = "orange"
        recommendation = "Upgrade TLS version. Replace weak ciphers with AES-256-GCM"
    else:
        status = "Critical"
        risk_level = "critical"
        color = "red"
        recommendation = "Immediately replace cipher. Upgrade to TLS 1.3 with AES-256-GCM"
    
    return {
        "score": total,
        "status": status,
        "risk_level": risk_level,
        "color": color,
        "recommendation": recommendation,
        "tls_score": tls_score,
        "cipher_score": cipher_score,
        "key_score": key_score,
        "pqc_score": pqc_score
    }
