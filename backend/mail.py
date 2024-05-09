#!/usr/bin/env python3
import ssl
import smtplib
import imaplib
from rich.console import Console
from cryptography import x509
import tls_utils
from tls_utils import TLSDetails
from abc import ABC, abstractmethod

class MailHandler(ABC):
    def __init__(self, host: str, port: int, context: ssl.SSLContext):
        self.host = host
        self.port = port
        self.context = context
    
    def connect(self, verification: bool) -> tuple[bool, int]:
        connection = self.protocol_init(self.host, self.port)
        if verification:
            connection.starttls(**self.protocol_starttls_args())
        else:
            connection.starttls()
        cert = connection.sock.getpeercert()
        self.protocol_close(connection)
        return tls_utils.get_validity_days(cert)

    @abstractmethod
    def protocol_init(self, host, port):
        raise NotImplementedError()
    @abstractmethod
    def protocol_close(self, connection):
        raise NotImplementedError()
    @abstractmethod
    def protocol_starttls_args(self):
        raise NotImplementedError()
    
    @staticmethod
    def create_handler(protocol: str):
        if protocol == "smtp":
            return SMTPHandler
        elif protocol == "imap":
            return IMAPHandler
        else:
            raise ValueError("Invalid protocol")

class IMAPHandler(MailHandler):
    def protocol_init(self, host, port):
        return imaplib.IMAP4(host, port)
    def protocol_close(self, connection):
        connection.logout()
    def protocol_starttls_args(self):
        return {"ssl_context": self.context}

class SMTPHandler(MailHandler):
    def protocol_init(self, host, port):
        return smtplib.SMTP(host, port)
    def protocol_close(self, connection):
        connection.quit()
    def protocol_starttls_args(self):
        return {"context": self.context}

class MailVerificator:
    def __init__(self, context: ssl.SSLContext):
        self.context = context

    def connect(self, domain: str, port: int, protocol: str) -> TLSDetails:
        mail = MailHandler.create_handler(protocol)(domain, port, self.context)
        try:
            expiry = mail.connect(True)[1]
            return TLSDetails(domain_name=domain, expires_in_days=expiry)
        except ssl.SSLCertVerificationError as e:
            if (e.verify_code == 10):
                expiry = mail.connect(False)[1]
                return TLSDetails(domain_name=domain, expires_in_days=expiry)
            else:
                error = "failed verification:", e.verify_message + "."
                return TLSDetails(domain_name=domain, error_message=error)