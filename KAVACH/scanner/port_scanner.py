import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_PORTS = [
    21,   # FTP
    22,   # SSH
    23,   # Telnet
    25,   # SMTP
    53,   # DNS
    80,   # HTTP
    110,  # POP3
    143,  # IMAP
    443,  # HTTPS
    3306, # MySQL
    3389, # RDP
    5432, # PostgreSQL
    8080, # HTTP-Alt
    8443  # HTTPS-Alt
]

def scan_port(host, port, timeout=1.5):
    """Attempt to connect to a single port and return it if open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            if result == 0:
                return port
    except Exception:
        pass
    return None

def get_open_ports(host):
    """
    Scans a predefined list of common security ports concurrently.
    Returns a comma-separated string of open ports.
    """
    if not host or host == 'N/A':
        return ""
        
    open_ports = []
    
    # We use a ThreadPoolExecutor to scan scanning ports concurrently
    with ThreadPoolExecutor(max_workers=len(COMMON_PORTS)) as executor:
        future_to_port = {executor.submit(scan_port, host, port): port for port in COMMON_PORTS}
        
        for future in as_completed(future_to_port):
            port = future.result()
            if port is not None:
                open_ports.append(port)
                
    # Sort them numerically and format as string
    open_ports.sort()
    return ", ".join(str(p) for p in open_ports)

if __name__ == "__main__":
    # Test script locally
    test_host = "google.com"
    print(f"Scanning {test_host}...")
    ports = get_open_ports(test_host)
    print(f"Open ports: {ports}")
