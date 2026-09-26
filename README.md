# PKIMaster

PKIMaster is a lightweight Python PKI management application that runs on Debian 13 and can operate as a Root CA, Intermediate CA, or Issuing CA through a browser-based interface.

## Features

- Create self-signed Root CAs
- Create Intermediate and Issuing CAs signed by a parent CA
- Issue end-entity certificates from any managed CA
- Download certificates, private keys, and full chains in PEM format
- Persist CA and certificate metadata in SQLite
- Expose a `/healthz` endpoint for deployment health checks

## Debian 13 Quick Start

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv
python3 -m venv .venv
. .venv/bin/activate
pip install --upgrade pip
pip install -e .
pkimaster
```

Then open `http://127.0.0.1:8000`.

## Configuration

- `PKIMASTER_HOST` default: `127.0.0.1`
- `PKIMASTER_PORT` default: `8000`
- `PKIMASTER_DB_PATH` default: `instance/pkimaster.sqlite`
- `PKIMASTER_SECRET_KEY` default: `dev-only-change-me`

## Tests

```bash
python -m unittest discover -s tests
```
