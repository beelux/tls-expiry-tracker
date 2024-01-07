#!/usr/bin/env python3
import json
import ssl
import smtplib
import imaplib
import socket
from rich.console import Console
from cryptography import x509
import datetime
import math

def get_expiry_timestamps(expiry_timestamp: int, now_timestamp: int = datetime.datetime.now().timestamp()) -> (bool, int):
    seconds_left = expiry_timestamp - now_timestamp
    days_left = math.floor(seconds_left / 86400)
    return (seconds_left >= 0,days_left)

def get_validity_days(cert) -> (bool, int):
    # Get expiry date
    notAfter = cert['notAfter']
    notAfter_date = datetime.datetime.strptime(notAfter, '%b %d %H:%M:%S %Y %Z')

    # datetime to UNIX time
    notAfter_timestamp = notAfter_date.timestamp()
    expiry = get_expiry_timestamps(notAfter_timestamp)
    return (expiry[0], abs(expiry[1]))

console = Console()

# Parse the input file
with open('input.json') as raw_data:
    input = json.load(raw_data)

console.log("[white]Checking web domains...")

context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)

def web_noconn_expiry_days(web_domain: str) -> int | None:
    try:
        pem_cert = ssl.get_server_certificate((web_domain, 443), timeout=5)
        cert = x509.load_pem_x509_certificate(pem_cert.encode())
    except Exception as e:
        console = Console()
        console.log("Could not grab server cert for", "[orange bold underline]"+web_domain, ":", e, style="orange")
        return None
    
    not_after = cert.not_valid_after.timestamp()
    return get_expiry_timestamps(not_after)

for web_domain in input["domains"]["web"]:
    # Initiate TLS connection
    with context.wrap_socket(socket.socket(), server_hostname=web_domain) as s:
        try:
            s.connect((web_domain, 443))
            cert = s.getpeercert()
        except ssl.SSLCertVerificationError as e:
            saved = e
            if e.verify_code == 10:
                expiry = web_noconn_expiry_days(web_domain)[1]
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

    validity = get_validity_days(cert)[1]
    # Print expiry date
    console.log("[green bold underline]" + web_domain, "expires in", validity, "days", style="green")
    # TODO: remove known expired certs
    # If the cert was expired before, we know that it is now valid
    # -> remove it from the list of expirjuded certs

def __mail_connection(host, port, verification: bool, initializer, starttls_args, closer) -> (bool, int):
    connection = initializer(host, port)
    if verification:
        connection.starttls(**starttls_args)
    else:
        connection.starttls()
    cert = connection.sock.getpeercert()
    closer(connection)
    return get_validity_days(cert)

def __smtp_closing(connection):
    connection.quit()
    
def __smtp_connection(domain, port, verification: bool) -> (bool, int):
    initializer = smtplib.SMTP
    starttls_args = {"context": context}
    return __mail_connection(domain, port, verification, initializer, starttls_args, __smtp_closing)

def __imap_closing(connection):
    connection.logout()

def __imap_connection(domain, port, verification: bool) -> (bool, int):
    initializer = imaplib.IMAP4
    starttls_args = {"ssl_context": context}
    return __mail_connection(domain, port, verification, initializer, starttls_args, __imap_closing)

def __mail_connect(domain, port, protocol_func):
    try:
        expiry = protocol_func(domain, port, True)[1]
        console.log("[green bold underline]" + domain, "expires in", expiry, "days", style="green")
    except ssl.SSLCertVerificationError as e:
        if (e.verify_code == 10):
            expiry = protocol_func(domain, port, False)[1]
            console.log("[red bold underline]" + web_domain, "expired", abs(expiry), "days ago.", style="red")
        else:
            console.log("[red bold underline]" + domain, "failed verification:", e.verify_message + ".", style="red")

def smtp_connect(domain, port):
    __mail_connect(domain, port, __smtp_connection)

def imap_connect(domain, port):
    __mail_connect(domain, port, __imap_connection)

for smtp_entry in input["domains"]["smtp"]:
    smtp_connect(smtp_entry["host"], smtp_entry["port"])

for imap_entry in input["domains"]["imap"]:
    imap_connect(imap_entry["host"], imap_entry["port"])
