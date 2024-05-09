from abc import ABC, abstractmethod
import ssl
from tls_utils import TLSDetails, EXPIRED, REVOKED, SELF_SIGNED, ROOT_NOT_TRUSTED

class GenericHandler(ABC):
    def __init__(self, host: str, port: int, context: ssl.SSLContext):
        self.host = host
        self.port = port
        self.context = context

    @abstractmethod
    def connect(self, verification: bool) -> int:
        raise NotImplementedError()

    @staticmethod
    def create_handler(protocol: str):
        import web, mail
        if protocol == "smtp":
            return mail.SMTPHandler
        elif protocol == "imap":
            return mail.IMAPHandler
        elif protocol == "ssl" or protocol == "tls" or protocol == "https":
            return web.SSLHandler
        else:
            raise ValueError("Invalid protocol")

class Verificator:
    def __init__(self, context: ssl.SSLContext):
        self.context = context
    def connect(self, domain: str, port: int, protocol: str) -> TLSDetails:
        handler = GenericHandler.create_handler(protocol)(domain, port, self.context)
        try:
            expiry = handler.connect(True)
            return TLSDetails(domain_name=domain, expires_in_days=expiry)
        except ssl.SSLCertVerificationError as e:
            if e.verify_code == EXPIRED:
                expiry = handler.connect(False)
                return TLSDetails(domain_name=domain, expires_in_days=expiry)
            elif e.verify_code == REVOKED:
                # This never happens, as we do not have any CRLs or OCSP set up :(
                # It's a massive pain and I'm not sure it's worth the considerable extra code
                # Maybe look into MetLife/OCSPChecker but idk
                return TLSDetails(domain_name=domain, error_message="was revoked.")
            elif e.verify_code == SELF_SIGNED:
                return TLSDetails(domain_name=domain, error_message="is self-signed.")
            elif e.verify_code == ROOT_NOT_TRUSTED:
                return TLSDetails(domain_name=domain, error_message="invalid: root not trusted.")
            else:
                return TLSDetails(domain_name=domain, error_message="failed verification: " + e.verify_message + ".")
        except ssl.SSLError as e:
            return TLSDetails(domain_name=domain, error_message="could not establish a secure connection: " + e.reason + ".")
        except Exception as e:
            return TLSDetails(domain_name=domain, error_message="could not connect: " + str(e) + ".")