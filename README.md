# PKIMaster

PKIMaster is a lightweight Python PKI management application that runs on Debian 13 and can operate as a Root CA, Intermediate CA, or Issuing CA through a browser-based interface.

## Features

- Create self-signed Root CAs
- Create Intermediate and Issuing CAs signed by a parent CA
- Issue end-entity certificates from managed Issuing CAs
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
export PKIMASTER_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export PKIMASTER_KEY_ENCRYPTION_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
python -m flask --app app:create_app run --host 127.0.0.1 --port 8000
```

Then open `http://127.0.0.1:8000`.

For production-style hosting behind a reverse proxy, point your WSGI server at `wsgi:app`.

## Configuration

- `PKIMASTER_HOST` default: `127.0.0.1`
- `PKIMASTER_PORT` default: `8000`
- `PKIMASTER_DB_PATH` default: `instance/pkimaster.sqlite`
- `PKIMASTER_SECRET_KEY` required
- `PKIMASTER_ADMIN_TOKEN` default: unset (private-key downloads stay disabled)
- `PKIMASTER_KEY_ENCRYPTION_SECRET` required

`PKIMASTER_SECRET_KEY` and `PKIMASTER_KEY_ENCRYPTION_SECRET` must be set to unique deployment secrets before starting the application. The app stores encrypted private keys and will refuse to boot without both values.

## Tests

```bash
python -m unittest discover -s tests
```
