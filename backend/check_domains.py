#!/usr/bin/env python3
import json
import ssl
import os
from rich.console import Console

from web import SSLVerificator
from mail import MailVerificator

if __name__ == "__main__":
    console = Console()

    # Parse the input file
    path = os.path.split(__file__)[0] + "/"
    with open(path + 'input.json') as raw_data:
        input = json.load(raw_data)

    context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)

    console.log("[white]Checking web domains...")

    ssl = SSLVerificator(context)
    for web_domain in input["domains"]["web"]:
        result = ssl.connect(web_domain, 443)
        result.print(console)

    mail = MailVerificator(context)
    for smtp_entry in input["domains"]["smtp"]:
        result = mail.connect(smtp_entry["host"], smtp_entry["port"], "smtp")
        result.print(console)

    for imap_entry in input["domains"]["imap"]:
        result = mail.connect(imap_entry["host"], imap_entry["port"], "imap")
        result.print(console)
