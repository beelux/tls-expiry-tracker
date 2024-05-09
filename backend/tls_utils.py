#!/usr/bin/env python3
from rich.console import Console
import datetime
import math

EXPIRED = 10
REVOKED = 23
SELF_SIGNED = 18
ROOT_NOT_TRUSTED = 19

class TLSDetails:
    domain_name = None
    expires_in_days = None
    error_message = None
    connection_error = False

    def __init__(self, domain_name : str = None, expires_in_days : str = None, error_message : str = None, connection_error : bool = False):
        self.domain_name = domain_name
        self.expires_in_days = expires_in_days
        self.error_message = error_message
        self.connection_error = connection_error
    
    def print(self, console: Console):
        if self.connection_error:
            console.log("[orange bold underline]" + self.domain_name, self.error_message, style="orange")
        elif self.error_message != None:
            console.log("[red bold underline]" + self.domain_name, self.error_message, style="red")
        elif self.expires_in_days < 0:
            console.log("[red bold underline]" + self.domain_name, "expired", abs(self.expires_in_days), "days ago.", style="red")
        else:
            console.log("[green bold underline]" + self.domain_name, "expires in", self.expires_in_days, "days", style="green")

def get_expiry_timestamps(expiry_timestamp: int, now_timestamp: int = datetime.datetime.now(datetime.UTC).timestamp()) -> tuple[bool, int]:
    seconds_left = expiry_timestamp - now_timestamp
    days_left = math.floor(seconds_left / 86400)
    return (seconds_left >= 0, days_left)

def get_validity_days(cert) -> tuple[bool, int]:
    # Get expiry date
    notAfter = cert['notAfter']
    notAfter_date = datetime.datetime.strptime(notAfter, '%b %d %H:%M:%S %Y %Z')

    # datetime to UNIX time
    notAfter_timestamp = notAfter_date.timestamp()
    expiry = get_expiry_timestamps(notAfter_timestamp)
    return (expiry[0], abs(expiry[1]))