import requests
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

def get_subdomains(domain):
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        subdomains = set()
        
        for entry in data:
            common_name = entry.get('common_name', '')
            name_value = entry.get('name_value', '')
            
            if common_name:
                for subdomain in common_name.split('\n'):
                    subdomain = subdomain.strip()
                    if subdomain and '*' not in subdomain and domain in subdomain and subdomain != domain:
                        subdomains.add(subdomain)
            
            if name_value:
                for subdomain in name_value.split('\n'):
                    subdomain = subdomain.strip()
                    if subdomain and '*' not in subdomain and domain in subdomain and subdomain != domain:
                        subdomains.add(subdomain)
        
        subdomains = sorted(list(subdomains))[:50]
        return subdomains
    except:
        return []

def resolve_ip(subdomain):
    try:
        return socket.gethostbyname(subdomain)
    except:
        return None

def resolve_ips_parallel(subdomains):
    results = {}
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_subdomain = {executor.submit(resolve_ip, sub): sub for sub in subdomains}
        for future in as_completed(future_to_subdomain):
            subdomain = future_to_subdomain[future]
            results[subdomain] = future.result()
    return results

def get_server_software(subdomain):
    try:
        response = requests.get(f"https://{subdomain}", timeout=5, verify=False)
        server = response.headers.get('Server')
        return server if server else "Unknown"
    except:
        return "Unreachable"
