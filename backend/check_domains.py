#!/usr/bin/env python3
import json
import ssl
import socket
import os
from rich.console import Console
from cryptography import x509

import web
from mail import *
import tls_utils

if __name__ == "__main__":
    console = Console()

    # Parse the input file
    path = os.path.split(__file__)[0] + "/"
    with open(path + 'input.json') as raw_data:
        input = json.load(raw_data)

    context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)

    console.log("[white]Checking web domains...")

    for web_domain in input["domains"]["web"]:
        # Initiate TLS connection
        with context.wrap_socket(socket.socket(), server_hostname=web_domain) as s:
            try:
                s.connect((web_domain, 443))
                cert = s.getpeercert()
            except ssl.SSLCertVerificationError as e:
                saved = e
                if e.verify_code == 10:
                    expiry = web.web_noconn_expiry_days(web_domain)[1]
                    if(expiry != None):
                        # TODO: add the TLS expiry stuff here
                        # possibly a list of domains that have expired
                        # if its already in here, dont add it again
                        console.log("[red bold underline]" + web_domain, "expired", abs(expiry), "days ago.", style="red")
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

        validity = tls_utils.get_validity_days(cert)[1]
        # Print expiry date
        console.log("[green bold underline]" + web_domain, "expires in", validity, "days", style="green")
        # TODO: remove known expired certs
        # If the cert was expired before, we know that it is now valid
        # -> remove it from the list of expirjuded certs

    mail = MailVerificator(context)
    for smtp_entry in input["domains"]["smtp"]:
        result = mail.connect(smtp_entry["host"], smtp_entry["port"], "smtp")
        result.print(console)

    for imap_entry in input["domains"]["imap"]:
        result = mail.connect(imap_entry["host"], imap_entry["port"], "imap")
        result.print(console)
