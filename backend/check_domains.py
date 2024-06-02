#!/usr/bin/env python3
import json
import ssl
import os
from rich.console import Console
from generic_handler import Verificator

if __name__ == "__main__":
    console = Console()

    # Parse the input file
    path = os.path.split(__file__)[0] + "/"
    with open(path + 'input.json') as raw_data:
        input = json.load(raw_data)

    context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)

    console.log("[white]Checking web domains...")

    v = Verificator(context)
    for https_entry in input["domains"]["https"]:
        # HTTPS (TLS) w/ 443
        result = v.connect(https_entry, 443, "ssl")
        result.print(console)

    for tls_entry in input["domains"]["tls"]:
        # TLS w/ custom port
        result = v.connect(tls_entry["host"], tls_entry["port"], "ssl")
        result.print(console)

    for smtp_entry in input["domains"]["smtp"]:
        # SMTP w/ STARTTLS
        result = v.connect(smtp_entry["host"], smtp_entry["port"], "smtp")
        result.print(console)

    for imap_entry in input["domains"]["imap"]:
        # IMAP w/ STARTTLS
        result = v.connect(imap_entry["host"], imap_entry["port"], "imap")
        result.print(console)
