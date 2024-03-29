# X days since last outage caused by TLS expiry

How often does your infrastructure break because you forgot to automate TLS renewal, or because it broke?

Find out by rolling out this tool with the domains and services!

## Guide: how to set up

To set up the backend:

- `cd backend`
- `python -m venv venv`
- `source venv/bin/activate`
- `pip install -r requirements.txt`

## Plans (TODO)

### Backend

- Python script for backend
- check each domain's tls cert using [`ssl` library](https://docs.python.org/3/library/ssl.html)
- use file(s) to store:
  - domains
  - expiry status *per* domain
  - log of outages
- cronjob at the start (every 1-5 minutes)
