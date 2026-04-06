def check_pqc(tls_version, cipher_suite, key_length, key_type="Unknown"):
    """
    Evaluates cryptography against NIST PQC standards out of 1000 points.
    Returns dict: score, status, label, color, recommendation.
    """
    
    score_tls = 0
    score_cipher = 0
    score_key = 0
    score_pqc = 0
    
    # 1. TLS Version (250)
    tls = (tls_version or "").upper()
    if "1.3" in tls:
        score_tls = 250
    elif "1.2" in tls:
        score_tls = 150
    elif "1.1" in tls:
        score_tls = 50
    else:
        score_tls = 0
        
    # 2. Cipher Suite (250)
    cipher = (cipher_suite or "").upper()
    if "AES256-GCM" in cipher or "AES-256-GCM" in cipher:
        score_cipher = 250
    elif "AES128-GCM" in cipher or "AES-128-GCM" in cipher:
        score_cipher = 200
    elif "CHACHA20" in cipher:
        score_cipher = 200
    elif "AES256" in cipher and "CBC" in cipher:
        score_cipher = 100
    elif "AES128" in cipher and "CBC" in cipher:
        score_cipher = 50
    else:
        score_cipher = 0
        
    # 3. Key Strength (250)
    kl = 0
    try:
        kl = int(key_length or 0)
    except ValueError:
        kl = 0
    
    kt = (key_type or "Unknown").upper()
    
    if kt == "EC":
        if kl >= 384:
            score_key = 250
        elif kl >= 256:
            score_key = 200
        else:
            score_key = 0
    elif kt == "EDDSA":
        score_key = 250
    else:
        # Default to RSA/DSA/Unknown thresholds
        if kl >= 4096:
            score_key = 250
        elif kl >= 3072:
            score_key = 200
        elif kl >= 2048:
            score_key = 150 # Standard for RSA
        elif kl >= 1024:
            score_key = 75
        else:
            score_key = 0
        
    # 4. PQC Compliance (250)
    if "ML-KEM" in cipher or "KYBER" in cipher:
        score_pqc = 250
    elif "HYBRID" in cipher:
        score_pqc = 175
    elif score_tls == 250: # TLS 1.3 best effort if no strict PQC cipher detected
        score_pqc = 100
    elif score_tls == 150:
        score_pqc = 50
    else:
        score_pqc = 0
        
    total_score = score_tls + score_cipher + score_key + score_pqc
    
    status = ""
    color = ""
    recommendation = ""
    risk_level = ""
    
    if total_score > 700:
        status = "Elite-PQC"
        color = "text-green-500"
        risk_level = "low"
        recommendation = "Maintain current quantum-safe standards."
    elif total_score >= 400:
        status = "Standard"
        color = "text-yellow-500"
        risk_level = "medium"
        recommendation = "Upgrade to TLS 1.3 and hybrid ML-KEM exchange to attain Elite-PQC status."
    elif total_score >= 100:
        status = "Legacy"
        color = "text-orange-500"
        risk_level = "high"
        recommendation = "Deprecate legacy protocols immediately. Adopt AES-256-GCM or ChaCha20."
    else:
        status = "Critical"
        color = "text-red-500"
        risk_level = "critical"
        recommendation = "Urgent: Infrastructure is vulnerable to 'Store-Now-Decrypt-Later' attacks. Rotate keys and update server."

    return {
        "pqc_score": total_score,
        "pqc_status": status,
        "risk_level": risk_level,
        "color": color,
        "recommendation": recommendation,
        "details": {
            "tls_score": score_tls,
            "cipher_score": score_cipher,
            "key_score": score_key,
            "compliance_score": score_pqc
        }
    }
