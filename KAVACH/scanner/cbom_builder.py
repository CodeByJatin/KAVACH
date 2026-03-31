def build_cbom_data(assets):
    """
    Aggregates asset data into dicts ready for Chart.js.
    `assets` is a list of sqlite3.Row or dict objects from the database.
    """
    ciphers = {}
    key_lengths = {}
    cas = {}
    tls_versions = {}
    
    total_assets = len(assets)
    scanned_assets = len([a for a in assets if not a['scan_error']])
    weak_assets = 0
    pqc_elite = 0
    
    for a in assets:
        if a['scan_error']:
            continue
            
        # ciphers
        c = a['cipher_suite'] or "Unknown"
        ciphers[c] = ciphers.get(c, 0) + 1
        
        # key levels
        kl = str(a['key_length'] or "Unknown")
        if kl != "Unknown":
            kl = f"{kl} bits"
        key_lengths[kl] = key_lengths.get(kl, 0) + 1
        
        # CAs
        ca = a['cert_authority'] or "Unknown"
        cas[ca] = cas.get(ca, 0) + 1
        
        # TLS
        tls = a['tls_version'] or "Unknown"
        tls_versions[tls] = tls_versions.get(tls, 0) + 1
        
        # stats
        if a['pqc_score'] and a['pqc_score'] < 400:
            weak_assets += 1
        if a['pqc_score'] and a['pqc_score'] > 700:
            pqc_elite += 1
            
    return {
        "ciphers": {"labels": list(ciphers.keys()), "data": list(ciphers.values())},
        "key_lengths": {"labels": list(key_lengths.keys()), "data": list(key_lengths.values())},
        "cas": {"labels": list(cas.keys()), "data": list(cas.values())},
        "tls_versions": {"labels": list(tls_versions.keys()), "data": list(tls_versions.values())},
        "stats": {
            "total_assets": total_assets,
            "scanned_assets": scanned_assets,
            "weak_assets": weak_assets,
            "pqc_elite": pqc_elite
        }
    }
