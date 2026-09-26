#!/bin/sh
# Run only in a disposable Debian 13 machine/container as root.
set -eu

if [ "$(id -u)" -ne 0 ] || [ "$#" -ne 1 ]; then
    echo "Usage: sudo sh scripts/smoke-deb.sh /absolute/path/pkimaster.deb" >&2
    exit 2
fi
if [ -e /var/lib/pkimaster ] || dpkg-query -W pkimaster >/dev/null 2>&1; then
    echo "Refusing to alter an existing PKIMaster installation or state directory." >&2
    exit 2
fi
package=$(realpath "$1")
repository=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
service_pid=
temporary=$(mktemp -d)
cleanup() {
    if [ -n "$service_pid" ]; then
        kill "$service_pid" 2>/dev/null || true
        wait "$service_pid" 2>/dev/null || true
    fi
    rm -r -- "$temporary"
}
trap cleanup EXIT INT TERM

start_service() {
    if [ -d /run/systemd/system ]; then
        systemctl start pkimaster
    else
        runuser -u _pkimaster -- python3 /usr/lib/pkimaster/pkimaster_server.py >"$temporary/service.log" 2>&1 &
        service_pid=$!
    fi
    attempts=0
    until curl --silent --fail --cacert /var/lib/pkimaster/server-tls/bootstrap.pem https://127.0.0.1:8443/healthz >"$temporary/health.json"; do
        attempts=$((attempts + 1))
        if [ "$attempts" -ge 30 ]; then
            cat "$temporary/service.log" 2>/dev/null || journalctl -u pkimaster --no-pager
            exit 1
        fi
        sleep 1
    done
}
stop_service() {
    if [ -d /run/systemd/system ]; then
        systemctl stop pkimaster
    elif [ -n "$service_pid" ]; then
        kill "$service_pid"
        wait "$service_pid" || true
        service_pid=
    fi
}

apt-get install -y "$package"
systemd-analyze verify /usr/lib/systemd/system/pkimaster.service
start_service
curl --silent --fail --cacert /var/lib/pkimaster/server-tls/bootstrap.pem https://127.0.0.1:8443/setup >"$temporary/setup.html"
grep -q 'csrf_token' "$temporary/setup.html"
python3 "$repository/scripts/smoke-web.py" "$temporary"
test "$(stat -c %a /var/lib/pkimaster)" = 700
test "$(stat -c %a /var/lib/pkimaster/server-tls/bootstrap.pem)" = 600
sha256sum /var/lib/pkimaster/runtime-secrets.json /var/lib/pkimaster/server-tls/bootstrap.pem >"$temporary/identity.sha256"
stop_service

# Upgrade/reinstall must preserve identities and allow the service to restart.
apt-get install -y --reinstall "$package"
start_service
sha256sum --check "$temporary/identity.sha256"
python3 "$repository/scripts/smoke-web.py" "$temporary" --verify-upgrade
stop_service

# Both removal modes deliberately retain all CA material and its owner.
apt-get remove -y pkimaster
sha256sum --check "$temporary/identity.sha256"
apt-get purge -y pkimaster
sha256sum --check "$temporary/identity.sha256"
test -f /var/lib/pkimaster/pkimaster.sqlite
getent passwd _pkimaster >/dev/null
echo 'Package HTTPS, reinstall, remove and purge smoke checks passed.'
