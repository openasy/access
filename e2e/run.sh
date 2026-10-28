#!/bin/bash
# End-to-end: a real OpenSSH server trusts Access, and a real ssh client logs in with a certificate Access signed,
# only after someone else approved, only as the account asked for, and not once the access is revoked (ADR 0061).
# Needs Docker, ssh and ssh-keygen, and the image to test (default access:dev). Exits non-zero on failure.
set -eu
IMAGE=${1:-access:dev}
D=$(mktemp -d)
cleanup() { docker rm -f e2e-access e2e-sshd >/dev/null 2>&1 || true; docker network rm e2e-access >/dev/null 2>&1 || true; }
cleanup
trap cleanup EXIT
docker network create e2e-access >/dev/null
openssl rand -hex 32 > "$D/kek"
chmod 644 "$D/kek"
docker run -d --name e2e-access --network e2e-access -p 18081:8080 -e ACCESS_PUBLIC_URL=http://localhost:18081 \
  -v "$D/kek:/run/secrets/openasy-kek:ro" "$IMAGE" >/dev/null
# A plain Debian with OpenSSH, as a server people log in to. The accounts exist; nobody has a key in authorized_keys.
docker run -d --name e2e-sshd --network e2e-access -p 127.0.0.1:12222:22 debian:trixie-slim sh -c \
  'apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends openssh-server curl >/dev/null && useradd -m deploy && useradd -m ops && mkdir -p /run/sshd && touch /ready && sleep infinity' >/dev/null
for _ in $(seq 1 30); do curl -sf localhost:18081/readyz >/dev/null && break; sleep 1; done
for _ in $(seq 1 180); do docker exec e2e-sshd test -f /ready 2>/dev/null && break; sleep 1; done
docker exec e2e-sshd test -f /ready || { echo "FAIL the SSH server did not start"; docker logs e2e-sshd; exit 1; }
SETUP=$(docker logs e2e-access 2>&1 | grep -o 'http://localhost:18081/?setup=[A-Za-z0-9_-]*' | tail -1)
node "$(dirname "$0")/flow.ts" "$SETUP" "$D"
