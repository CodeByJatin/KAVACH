from sslyze import (
    Scanner,
    ServerScanRequest,
    ServerNetworkLocation,
    ScanCommand,
)
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
import hashlib


def scan_subdomain(subdomain, port=443):
    """
    Connects to the subdomain on port 443, extracts TLS info and cert info.
    Uses sslyze 6.x API.
    """
    try:
        print(f"  [sslyze] Scanning {subdomain}:{port} ...")
        network_loc = ServerNetworkLocation(hostname=subdomain, port=port)
        scan_req = ServerScanRequest(
            server_location=network_loc,
            scan_commands={
                ScanCommand.CERTIFICATE_INFO,
                ScanCommand.TLS_1_2_CIPHER_SUITES,
                ScanCommand.TLS_1_3_CIPHER_SUITES,
            }
        )

        scanner = Scanner()
        scanner.queue_scans([scan_req])

        result = None
        for r in scanner.get_results():
            result = r
            break

        if not result:
            return {"error": "No scan result returned"}

        # Check connectivity error
        if result.connectivity_error_trace:
            return {"error": f"Connection failed: {subdomain}"}

        scan_result = result.scan_result
        if not scan_result:
            return {"error": "Scan completed but no results"}

        # --- Extract TLS version and cipher ---
        tls_version = "Unknown"
        cipher = "Unknown"

        try:
            tls_1_3_attempt = scan_result.tls_1_3_cipher_suites
            if tls_1_3_attempt and tls_1_3_attempt.result and tls_1_3_attempt.result.accepted_cipher_suites:
                tls_version = "TLS 1.3"
                cipher = tls_1_3_attempt.result.accepted_cipher_suites[0].cipher_suite.name
        except Exception:
            pass

        try:
            if tls_version == "Unknown":
                tls_1_2_attempt = scan_result.tls_1_2_cipher_suites
                if tls_1_2_attempt and tls_1_2_attempt.result and tls_1_2_attempt.result.accepted_cipher_suites:
                    tls_version = "TLS 1.2"
                    cipher = tls_1_2_attempt.result.accepted_cipher_suites[0].cipher_suite.name
        except Exception:
            pass

        # --- Extract certificate details ---
        key_length = 0
        cert_expiry = None
        cert_authority = "Unknown"
        cert_common_name = "Unknown"
        cert_fingerprint = "Unknown"

        try:
            cert_info_attempt = scan_result.certificate_info
            if cert_info_attempt and cert_info_attempt.result:
                deployments = cert_info_attempt.result.certificate_deployments
                if deployments:
                    cert_chain = deployments[0].received_certificate_chain
                    if cert_chain:
                        cert = cert_chain[0]

                        # Key size
                        pub_key = cert.public_key()
                        key_length = getattr(pub_key, 'key_size', 0)

                        # Expiry
                        try:
                            # cryptography >= 42.x uses not_valid_after_utc
                            if hasattr(cert, 'not_valid_after_utc'):
                                cert_expiry = cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S")
                            elif hasattr(cert, 'not_valid_after'):
                                cert_expiry = cert.not_valid_after.strftime("%Y-%m-%d %H:%M:%S")
                        except Exception:
                            pass

                        # Issuer (CA)
                        try:
                            issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
                            if issuer_cn:
                                cert_authority = issuer_cn[0].value
                        except Exception:
                            pass

                        # Subject CN
                        try:
                            subject_cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                            if subject_cn:
                                cert_common_name = subject_cn[0].value
                        except Exception:
                            pass

                        # SHA256 fingerprint
                        try:
                            der_cert = cert.public_bytes(serialization.Encoding.DER)
                            cert_fingerprint = hashlib.sha256(der_cert).hexdigest()
                        except Exception:
                            pass

        except Exception as ce:
            print(f"  [sslyze] Cert extraction error for {subdomain}: {ce}")

        print(f"  [sslyze] Done {subdomain}: {tls_version} / {cipher} / key={key_length}")

        return {
            "tls_version": tls_version,
            "cipher_suite": cipher,
            "key_length": key_length,
            "cert_expiry": cert_expiry,
            "cert_authority": cert_authority,
            "cert_common_name": cert_common_name,
            "cert_fingerprint": cert_fingerprint,
            "error": None
        }

    except Exception as e:
        print(f"  [sslyze] Exception scanning {subdomain}: {e}")
        return {"error": str(e)}
