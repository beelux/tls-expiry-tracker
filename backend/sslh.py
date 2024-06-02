#!/usr/bin/env python3
import ssl
from cryptography import x509
import socket

import tls_utils
from generic_handler import GenericHandler

class SSLHandler(GenericHandler):
    def connect(self, verification: bool) -> int:
        if verification:
            with self.context.wrap_socket(socket.socket(), server_hostname=self.host) as s:
                s.connect((self.host, self.port))
                cert = s.getpeercert()
                return tls_utils.get_cert_expiry_timestamp(cert)
        else:
            pem_cert = ssl.get_server_certificate((self.host, self.port), timeout=5)
            cert = x509.load_pem_x509_certificate(pem_cert.encode())
            not_after = cert.not_valid_after_utc.timestamp()
            return not_after