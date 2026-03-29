import warnings
warnings.filterwarnings("ignore")

from scanner.tls_scanner import scan_subdomain

result = scan_subdomain("digi2wl.pnb.bank.in")
for key, value in result.items():
    print(f"{key}: {value}")
