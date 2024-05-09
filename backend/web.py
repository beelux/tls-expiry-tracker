#!/usr/bin/env python3
import ssl
from rich.console import Console
from cryptography import x509

import tls_utils as tls_utils

def web_noconn_expiry_days(web_domain: str) -> int | None:
    try:
        pem_cert = ssl.get_server_certificate((web_domain, 443), timeout=5)
        cert = x509.load_pem_x509_certificate(pem_cert.encode())
    except Exception as e:
        console = Console()
        console.log("Could not grab server cert for", "[orange bold underline]"+web_domain, ":", e, style="orange")
        return None
    
    not_after = cert.not_valid_after.timestamp()
    return tls_utils.get_expiry_timestamps(not_after)