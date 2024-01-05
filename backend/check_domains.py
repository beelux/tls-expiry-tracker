#!/usr/bin/env python3
import json
import ssl
import socket
from rich.console import Console
from cryptography import x509
import datetime
import math

def get_expiry_days(expiry_timestamp: int, now_timestamp: int = datetime.datetime.now().timestamp()) -> int:
    expiry_seconds = now_timestamp - expiry_timestamp
    expiry_days = math.floor(expiry_seconds / 86400)
    return expiry_days

def web_noconn_expiry_days(web_domain: str) -> int | None:
    try:
        pem_cert = ssl.get_server_certificate((web_domain, 443), timeout=5)
        cert = x509.load_pem_x509_certificate(pem_cert.encode())
    except Exception as e:
        console = Console()
        console.log("Could not grab server cert for", "[orange bold underline]"+web_domain, ":", e, style="orange")
        return None
    
    not_after = cert.not_valid_after.timestamp()
    return get_expiry_days(not_after)


console = Console()

# Parse the input file
with open('input.json') as raw_data:
    input = json.load(raw_data)

console.log("[white]Checking web domains...")

context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)

for web_domain in input["domains"]["web"]:
    # Initiate TLS connection
    with context.wrap_socket(socket.socket(), server_hostname=web_domain) as s:
        try:
            s.connect((web_domain, 443))
            cert = s.getpeercert()
        except ssl.SSLCertVerificationError as e:
            saved = e
            if e.verify_code == 10:
                expiry = web_noconn_expiry_days(web_domain)
                if(expiry != None):
                    # TODO: add the TLS expiry stuff here
                    # possibly a list of domains that have expired
                    # if its already in here, dont add it again
                    console.log("[red bold underline]" + web_domain, "expired", expiry, "days ago.", style="red")
            elif e.verify_code == 23:
                console.log("[red bold underline]" + web_domain, "was revoked.", style="red")
            elif e.verify_code == 18:
                console.log("[red bold underline]" + web_domain, "is self-signed.", style="red")
            elif e.verify_code == 19:
                console.log("[red bold underline]" + web_domain, "invalid: root not trusted.", style="red")
            else:
                console.log("[red bold underline]" + web_domain, "failed verification:", e.verify_message + ".", style="red")
            continue
        except ssl.SSLError as e:
            console.log("[orange bold underline]" + web_domain, "could not establish a secure connection:", e.reason, style="orange")
            continue
        except Exception as e:
            print(e)
            continue

    # Get expiry date
    expiry = cert['notAfter']
    expiry = datetime.datetime.strptime(expiry, '%b %d %H:%M:%S %Y %Z')

    # datetime to UNIX time
    expiry = expiry.timestamp()
    validity = abs(get_expiry_days(expiry))

    # Print expiry date
    console.log("[green bold underline]" + web_domain, "expires in", validity, "days", style="green")
    # TODO: remove known expired certs
    # If the cert was expired before, we know that it is now valid
    # -> remove it from the list of expired certs
