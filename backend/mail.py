#!/usr/bin/env python3
import ssl
import smtplib
import imaplib
from rich.console import Console
from cryptography import x509
import tls_utils
from generic_handler import GenericHandler
from abc import ABC, abstractmethod

class MailHandler(GenericHandler):
    def connect(self, verification: bool) -> int:
        connection = self.protocol_init(self.host, self.port)
        if verification:
            connection.starttls(**self.protocol_starttls_args())
        else:
            connection.starttls()
        cert = connection.sock.getpeercert()
        self.protocol_close(connection)
        return tls_utils.check_cert_validity(cert)[1]

    @abstractmethod
    def protocol_init(self, host, port):
        raise NotImplementedError()
    @abstractmethod
    def protocol_close(self, connection):
        raise NotImplementedError()
    @abstractmethod
    def protocol_starttls_args(self):
        raise NotImplementedError()

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