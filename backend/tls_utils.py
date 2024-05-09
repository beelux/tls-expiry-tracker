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

def compare_expiry_timestamps(expiry_timestamp: int, now_timestamp: int = datetime.datetime.now(datetime.UTC).timestamp()) -> tuple[bool, int]:
    seconds_left = expiry_timestamp - now_timestamp
    valid = seconds_left >= 0
    # We use floor(), which, when negative, will round towards -1
    if not valid:
        seconds_left = -seconds_left
    days_left = math.floor(seconds_left / 86400)
    # We need to restore the inversion
    if not valid:
        days_left = -days_left
    return (valid, days_left)

# Returns if the cert is valid, and the number of days left until expiry (negative if expired)
def check_cert_validity(cert) -> tuple[bool, int]:
    # Get expiry date
    notAfter = cert['notAfter']
    notAfter_date = datetime.datetime.strptime(notAfter, '%b %d %H:%M:%S %Y %Z')

    # datetime to UNIX time
    notAfter_timestamp = notAfter_date.timestamp()
    expiry = compare_expiry_timestamps(notAfter_timestamp)
    return (expiry[0], expiry[1])

# Test expiry checking (timestamps)
if __name__ == "__main__":
    console = Console()
    console.log("Time from rn (some time ago):", compare_expiry_timestamps(1715277129))
    console.log("Time from rn (in some time):", compare_expiry_timestamps(1715279129))