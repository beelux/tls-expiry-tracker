#!/usr/bin/env python3
from rich.console import Console
import datetime

EXPIRED = 10
REVOKED = 23
SELF_SIGNED = 18
ROOT_NOT_TRUSTED = 19

class TLSDetails:
    domain_name = None
    expiry_timestamp_utc = None
    error_message = None
    connection_error = False
    testing_timestamp_utc = None

    def __init__(self, domain_name : str = None, expiry_timestamp_utc : int = None, error_message : str = None, connection_error : bool = False, testing_timestamp_utc = datetime.datetime.now(datetime.UTC).timestamp()):
        self.domain_name = domain_name
        self.expiry_timestamp_utc = expiry_timestamp_utc
        self.error_message = error_message
        self.connection_error = connection_error
        self.testing_timestamp_utc = testing_timestamp_utc

    # Green - Valid
    # Orange - Non-TLS error
    # Red - TLS error
    def print(self, console: Console):
        if self.connection_error:
            console.log("[bold underline]" + self.domain_name, self.error_message, style="orange")
        elif self.error_message != None:
            console.log("[bold underline]" + self.domain_name, self.error_message, style="red")
        else:
            msg, future = self.relative_time_comparison()
            if not future:
                console.log("[bold underline]" + self.domain_name, "expired", msg + ".", style="red")
            else:
                console.log("[bold underline]" + self.domain_name, "expires", msg + ".", style="green")

    def is_valid(self) -> bool:
        if self.connection_error:
            return None
        return (self.error_message is None) and (not self.is_expired())

    def is_expired(self) -> bool:
        if self.expiry_timestamp_utc is None:
            return True
        # notAfter, so it includes the second itself
        return self.testing_timestamp_utc >= self.expiry_timestamp_utc

    # Returns a human-readable relative string, and if the date is future (true) or past (false)
    def relative_time_comparison(self, now = None) -> tuple[str, bool]:
        if self.expiry_timestamp_utc is None:
            return ""
        if now is None:
            now = self.testing_timestamp_utc

        diff = round(self.expiry_timestamp_utc) - round(now)
        future = diff > 0

        seconds_diff = int(abs(diff))
        minutes_diff = seconds_diff // 60
        hours_diff = minutes_diff // 60
        days_diff = hours_diff // 24
        months_diff = days_diff // 30

        msg = ""
        if months_diff > 0:
            days_diff = days_diff % 30
            msg += str(months_diff) + " month" + ("s" if months_diff > 1 else "")
            if future and months_diff < 3 and days_diff > 0:
                msg += " and " + str(days_diff) + " day" + ("s" if days_diff > 1 else "")
        elif days_diff > 0:
            msg += str(days_diff) + " day" + ("s" if days_diff > 1 else "")
        elif hours_diff > 0:
            msg += str(hours_diff) + " hour" + ("s" if hours_diff > 1 else "")
        elif minutes_diff > 0:
            msg += str(minutes_diff) + " minute" + ("s" if minutes_diff > 1 else "")
        elif seconds_diff > 0:
            msg += str(seconds_diff) + " second" + ("s" if seconds_diff > 1 else "")
        else:
            msg = "now"

        if future:
            if seconds_diff > 0:
                msg = "in " + msg
        else:
            if seconds_diff > 0:
                msg = msg + " ago"

        return (msg, future)

    def to_json(self):
        return self.__dict__

    @classmethod
    def from_json(cls, json_data):
        return cls(**json_data)

def get_cert_expiry_timestamp(cert) -> int:
    notAfter = cert['notAfter']
    notAfter_date = datetime.datetime.strptime(notAfter, '%b %d %H:%M:%S %Y %Z').astimezone(datetime.UTC)
    return notAfter_date.timestamp()

# Test expiry checking (timestamps)
if __name__ == "__main__":
    console = Console()

    test = TLSDetails(domain_name="now.example.org", expiry_timestamp_utc=datetime.datetime.now(datetime.UTC).timestamp())
    console.log("Now: ", test.relative_time_comparison())

    test = TLSDetails(domain_name="past.example.org", expiry_timestamp_utc=datetime.datetime.now(datetime.UTC).timestamp() - 1)
    console.log("Past: ", test.relative_time_comparison())

    test = TLSDetails(domain_name="future.example.org", expiry_timestamp_utc=datetime.datetime.now(datetime.UTC).timestamp() + 1)
    console.log("Future: ", test.relative_time_comparison())