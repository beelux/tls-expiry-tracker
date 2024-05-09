#!/usr/bin/env python3
import ssl
from rich.console import Console
from cryptography import x509
import socket

import tls_utils
from tls_utils import TLSDetails

class SSLHandler:
    def __init__(self, host: str, port: int, context: ssl.SSLContext):
        self.host = host
        self.port = port
        self.context = context

    def connect(self, verification: bool) -> int:
        if verification:
            with self.context.wrap_socket(socket.socket(), server_hostname=self.host) as s:
                s.connect((self.host, self.port))
                cert = s.getpeercert()
                return tls_utils.get_validity_days(cert)[1]
        else:
            pem_cert = ssl.get_server_certificate((self.host, self.port), timeout=5)
            cert = x509.load_pem_x509_certificate(pem_cert.encode())
            not_after = cert.not_valid_after_utc.timestamp()
            return tls_utils.get_expiry_timestamps(not_after)[1]

class SSLVerificator:
    def __init__(self, context: ssl.SSLContext):
        self.context = context

    def connect(self, domain: str, port: int) -> TLSDetails:
        handler = SSLHandler(domain, port, self.context)
        try:
            expiry = handler.connect(True)
            return TLSDetails(domain_name=domain, expires_in_days=expiry)
        except ssl.SSLCertVerificationError as e:
            if e.verify_code == tls_utils.EXPIRED:
                expiry = handler.connect(False)
                return TLSDetails(domain_name=domain, expires_in_days=expiry)
            elif e.verify_code == tls_utils.REVOKED:
                return TLSDetails(domain_name=domain, error_message="was revoked.")
            elif e.verify_code == tls_utils.SELF_SIGNED:
                return TLSDetails(domain_name=domain, error_message="is self-signed.")
            elif e.verify_code == tls_utils.ROOT_NOT_TRUSTED:
                return TLSDetails(domain_name=domain, error_message="invalid: root not trusted.")
            else:
                return TLSDetails(domain_name=domain, error_message="failed verification: " + e.verify_message + ".")
        except ssl.SSLError as e:
            return TLSDetails(domain_name=domain, error_message="could not establish a secure connection: " + e.reason + ".")
        except Exception as e:
            return TLSDetails(domain_name=domain, error_message="could not connect: " + str(e) + ".")