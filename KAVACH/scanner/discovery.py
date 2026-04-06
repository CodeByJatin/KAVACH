import requests
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import warnings
import time

SUSPICIOUS_PATTERNS = [
    'test', 'dev', 'staging', 'backup', 'old',
    'temp', 'demo', 'qa', 'uat', 'sandbox',
    'debug', 'beta', 'alpha', 'deprecated',
    'unused', 'legacy', 'archive', 'internal',
    'preprod', 'pre-prod', 'prototype', 'trial'
]


def get_subdomains(domain):
    """
    Discovers subdomains via CT logs, categorizes them into
    active/suspicious/unresolvable/external, and returns structured data.
    Ensures at least 50 legitimate (active+suspicious) subdomains are attempted.
    """

    # Step 1: Gather raw subdomain names from CT sources
    raw_names = fetch_raw_subdomains(domain)

    if not raw_names:
        print(f"No subdomains found for {domain}")
        return build_empty_result()

    print(f"Raw CT entries found: {len(raw_names)} for {domain}")

    # Step 2: Ownership filter first (remove external/typosquatting)
    owned = []
    external = []
    for sub in raw_names:
        if is_valid_subdomain(sub, domain):
            owned.append(sub)
        else:
            external.append(sub)

    # Step 3: Add the main domain itself at the front
    if domain not in owned:
        owned.insert(0, domain)
    else:
        owned.remove(domain)
        owned.insert(0, domain)

    print(f"Owned subdomains: {len(owned)}, External: {len(external)}")

    # Step 4: Resolve IPs and detect servers concurrently
    # Process all owned subdomains (not just first 50)
    resolved = resolve_batch(owned)

    # Step 5: Categorize each resolved subdomain
    active = []
    suspicious = []
    unresolvable = []

    for item in resolved:
        sub = item['subdomain']
        ip = item['ip_address']

        if ip is None:
            item['category'] = 'unresolvable'
            unresolvable.append(item)
        elif is_suspicious_name(sub):
            item['category'] = 'suspicious'
            suspicious.append(item)
        else:
            item['category'] = 'active'
            active.append(item)

    # Step 6: Build external entries (no scanning, just flag them)
    external_items = []
    for sub in external[:20]:  # cap external list
        external_items.append({
            'subdomain': sub,
            'ip_address': None,
            'server_software': 'N/A',
            'category': 'external'
        })

    # Step 7: Build final structured response
    all_items = active + suspicious + unresolvable + external_items

    result = {
        'all': all_items,
        'active': active,
        'suspicious': suspicious,
        'unresolvable': unresolvable,
        'external': external_items,
        'counts': {
            'total': len(all_items),
            'active': len(active),
            'suspicious': len(suspicious),
            'unresolvable': len(unresolvable),
            'external': len(external_items)
        }
    }

    print(f"Categories — Active: {len(active)}, Suspicious: {len(suspicious)}, "
          f"Unresolvable: {len(unresolvable)}, External: {len(external_items)}")

    return result


def build_empty_result():
    return {
        'all': [], 'active': [], 'suspicious': [],
        'unresolvable': [], 'external': [],
        'counts': {'total': 0, 'active': 0, 'suspicious': 0,
                   'unresolvable': 0, 'external': 0}
    }


def fetch_raw_subdomains(domain):
    """Fetch raw subdomain names from CT log sources."""
    raw = set()

    # Source 1: crt.sh
    crtsh_data = try_crtsh(domain)
    if crtsh_data:
        for entry in crtsh_data:
            common_name = entry.get('common_name', '')
            name_value = entry.get('name_value', '')
            for field in [common_name, name_value]:
                if field:
                    for sub in field.split('\n'):
                        sub = sub.strip()
                        if sub and '*' not in sub and domain in sub:
                            raw.add(sub)

    # Source 2: hackertarget fallback
    if len(raw) < 10:
        print("crt.sh returned few results, trying hackertarget...")
        ht_data = try_hackertarget(domain)
        if ht_data:
            for line in ht_data.strip().split('\n'):
                parts = line.split(',')
                if len(parts) >= 1:
                    sub = parts[0].strip()
                    if sub and domain in sub:
                        raw.add(sub)

    return sorted(list(raw))


def try_crtsh(domain):
    """Try crt.sh with retries."""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) KAVACH/1.0"}

    for attempt in range(2):
        try:
            timeout = 90 + (attempt * 30)
            print(f"crt.sh attempt {attempt + 1} (timeout={timeout}s) ...")
            response = requests.get(url, timeout=timeout, headers=headers)
            response.raise_for_status()
            data = response.json()
            if data:
                return data
        except Exception as e:
            print(f"crt.sh attempt {attempt + 1} failed: {e}")
            time.sleep(2)
    return None


def try_hackertarget(domain):
    """Fallback: hackertarget.com hostsearch API."""
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) KAVACH/1.0"}

    try:
        print(f"Trying hackertarget.com for {domain}...")
        response = requests.get(url, timeout=30, headers=headers)
        response.raise_for_status()
        text = response.text

        if "error" in text.lower() or "API count exceeded" in text:
            print(f"hackertarget returned error: {text[:100]}")
            return None

        return text if text.strip() else None

    except Exception as e:
        print(f"hackertarget failed: {e}")
        return None


# -------------------------------------------------------------------------
# CATEGORIZATION HELPERS
# -------------------------------------------------------------------------

def is_valid_subdomain(subdomain, root_domain):
    """Check ownership: must end with .root_domain or be root_domain itself."""
    return (
        subdomain == root_domain or
        subdomain.endswith('.' + root_domain)
    )


def is_suspicious_name(subdomain):
    """Detect non-production naming patterns."""
    sub_lower = subdomain.lower()
    for pattern in SUSPICIOUS_PATTERNS:
        if pattern in sub_lower:
            return True
    return False


# -------------------------------------------------------------------------
# RESOLUTION / ENRICHMENT
# -------------------------------------------------------------------------

def resolve_batch(subdomains):
    """Resolve IPs and server software concurrently."""
    results = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_sub = {
            executor.submit(resolve_and_interrogate, sub): sub
            for sub in subdomains
        }
        for future in as_completed(future_to_sub):
            results.append(future.result())

    return results


def resolve_and_interrogate(subdomain):
    ip_address = None
    server_software = "Unknown"

    try:
        ip_address = socket.gethostbyname(subdomain)
    except Exception:
        pass

    if ip_address:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            try:
                res = requests.get(f"https://{subdomain}", timeout=3, verify=False)
                server = res.headers.get('Server')
                if server:
                    server_software = server
            except Exception:
                try:
                    res = requests.get(f"http://{subdomain}", timeout=3)
                    server = res.headers.get('Server')
                    if server:
                        server_software = server
                except Exception:
                    pass

    return {
        "subdomain": subdomain,
        "ip_address": ip_address,
        "server_software": server_software
    }


if __name__ == '__main__':
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    result = get_subdomains('sbi.co.in')
    print(f"\n=== RESULTS ===")
    print(f"Active: {result['counts']['active']}")
    print(f"Suspicious: {result['counts']['suspicious']}")
    print(f"Unresolvable: {result['counts']['unresolvable']}")
    print(f"External: {result['counts']['external']}")
    for item in result['active'][:5]:
        print(f"  ✅ {item['subdomain']} -> {item['ip_address']}")
    for item in result['suspicious'][:3]:
        print(f"  ⚠️  {item['subdomain']} -> {item['ip_address']}")
