import warnings
warnings.filterwarnings("ignore")

from concurrent.futures import ThreadPoolExecutor, as_completed
from sslyze import Scanner, ServerScanRequest, ServerNetworkLocation, ScanCommand
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

def scan_subdomain(subdomain):
    result = {
        "subdomain": subdomain,
        "tls_version": None,
        "cipher_suite": None,
        "key_length": None,
        "cert_expiry": None,
        "cert_authority": None,
        "cert_common_name": None,
        "cert_fingerprint": None,
        "scan_error": None
    }

    try:
        location = ServerNetworkLocation(subdomain, 443)
        request = ServerScanRequest(
            server_location=location,
            scan_commands={
                ScanCommand.CERTIFICATE_INFO,
                ScanCommand.TLS_1_0_CIPHER_SUITES,
                ScanCommand.TLS_1_1_CIPHER_SUITES,
                ScanCommand.TLS_1_2_CIPHER_SUITES,
                ScanCommand.TLS_1_3_CIPHER_SUITES,
            }
        )

        scanner = Scanner()
        scanner.queue_scans([request])

        for scan_result in scanner.get_results():

            if scan_result.connectivity_error_trace:
                result["scan_error"] = "Could not connect"
                return result

            scan_data = scan_result.scan_result

            # ── TLS VERSION + CIPHER ──────────────────────────
            checks = [
                ("TLS 1.3", ScanCommand.TLS_1_3_CIPHER_SUITES, "tls_1_3_cipher_suites"),
                ("TLS 1.2", ScanCommand.TLS_1_2_CIPHER_SUITES, "tls_1_2_cipher_suites"),
                ("TLS 1.1", ScanCommand.TLS_1_1_CIPHER_SUITES, "tls_1_1_cipher_suites"),
                ("TLS 1.0", ScanCommand.TLS_1_0_CIPHER_SUITES, "tls_1_0_cipher_suites"),
            ]

            for tls_label, command, attr_name in checks:
                try:
                    attempt = getattr(scan_data, attr_name, None)
                    cipher_result = attempt.result if attempt else None  # ✅ unwrap
                    if cipher_result and cipher_result.accepted_cipher_suites:
                        result["tls_version"] = tls_label
                        result["cipher_suite"] = cipher_result.accepted_cipher_suites[0].cipher_suite.name
                        break
                except Exception:
                    continue

            # ── CERTIFICATE INFO ──────────────────────────────
            try:
                cert_info_attempt = scan_data.certificate_info
                cert_info = cert_info_attempt.result if cert_info_attempt else None  # ✅ unwrap

                if cert_info and cert_info.certificate_deployments:
                    deployment = cert_info.certificate_deployments[0]
                    cert = deployment.received_certificate_chain[0]

                    try:
                        result["cert_expiry"] = str(
                            cert.not_valid_after_utc
                            if hasattr(cert, "not_valid_after_utc")
                            else cert.not_valid_after
                        )
                    except Exception:
                        result["cert_expiry"] = None

                    try:
                        result["cert_common_name"] = cert.subject.get_attributes_for_oid(
                            NameOID.COMMON_NAME
                        )[0].value
                    except Exception:
                        result["cert_common_name"] = subdomain

                    try:
                        result["cert_authority"] = cert.issuer.get_attributes_for_oid(
                            NameOID.ORGANIZATION_NAME
                        )[0].value
                    except Exception:
                        result["cert_authority"] = "Unknown"

                    try:
                        pub_key = cert.public_key()
                        if hasattr(pub_key, "key_size"):
                            result["key_length"] = pub_key.key_size
                    except Exception:
                        result["key_length"] = None

                    try:
                        result["cert_fingerprint"] = cert.fingerprint(hashes.SHA256()).hex()
                    except Exception:
                        result["cert_fingerprint"] = None

            except Exception as e:
                result["scan_error"] = f"Cert error: {str(e)}"

    except Exception as e:
        result["scan_error"] = str(e)

    return result

def scan_subdomains_parallel(subdomains, max_workers=4):
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_sub = {
            executor.submit(scan_subdomain, sub): sub
            for sub in subdomains
        }
        for future in as_completed(future_to_sub):
            results.append(future.result())
    return results
