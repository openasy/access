# access

[![CI](https://github.com/openasy/access/actions/workflows/ci.yml/badge.svg)](https://github.com/openasy/access/actions/workflows/ci.yml)
[![Node.js 26 LTS](https://img.shields.io/badge/node-26%20LTS-339933?logo=nodedotjs&logoColor=white)](./.nvmrc)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue)](./LICENSE)

The [OpenAsy](https://github.com/openasy) Access product: **nobody holds a key to production when they are not using
it** (ADR 0061). Someone asks for SSH access to a server with a reason and a duration, someone else approves, and the
certificate they get works on that server only, as that account, until the access ends. Every request, approval and
certificate is in an audit log nobody can change.

```
Ece asks: deploy@web-1, 1 h, "INC-2291" ──▶ Lale approves ──▶ Ece pastes her public key
                                                                  │
                     web-1 trusts the Access CA ◀── ssh ── certificate: deploy@web-1, until 10:00
```

## How it works

- **Servers** are added by an admin with their policy: the Unix accounts one may ask for, the longest access (an hour
  unless set, at most a day) and how many people other than the requester must approve, one or two.
- **A request** names a server, an account, a duration and a reason, and optionally a ticket. One request per server
  and account may wait or be open at a time; a request nobody approves within a day (`ACCESS_PENDING_HOURS`) is
  cancelled.
- **Approval** is by an editor other than the requester. Nobody can approve or deny their own request, whatever their
  role; a try is refused and recorded. The access starts at the last approval the server needs and lasts as long as
  asked for.
- **Certificates.** While the access is open, the requester pastes their public key (`~/.ssh/id_ed25519.pub`; ECDSA,
  RSA of 2048 bits or more and security keys work too) and gets an OpenSSH certificate signed by the Access CA. Its
  principal is `account@server`, so it works on that server only; it expires when the access does, and its key ID
  (`ece@example.com access <request>`) is what sshd logs at each login. Private keys never leave people's computers.
- **Ending early.** The requester ends their own access when done; an editor revokes anyone's. Their certificates go
  on a revocation list that servers fetch every minute, until they would have expired.
- **A second factor at each step.** Asking for access, approving it and getting a certificate need a person signed in
  with an authenticator app or a passkey, or through an identity provider, which asks for its own. API tokens can
  never do any of them.

The CA is an Ed25519 key made on first start. Its private key is sealed with `openasy-kek` (ADR 0021) and never
leaves Access; Access does not start without that key, or with another one.

## A server

Add the server under Servers, then run the commands under Setup once on it, as root. For `web-1` with the account
`deploy` they are:

```bash
echo 'ssh-ed25519 AAAA... openasy-access' > /etc/ssh/openasy_access_ca.pub
install -d -m 755 /etc/ssh/openasy_access_principals
echo 'deploy@web-1' > /etc/ssh/openasy_access_principals/deploy
curl -sf -o /etc/ssh/openasy_access_revoked.krl https://access.example.com/api/v1/revoked.krl
echo '* * * * * root curl -sf -o ... && mv ...' > /etc/cron.d/openasy-access
cat > /etc/ssh/sshd_config.d/openasy-access.conf <<'OPENASY'
TrustedUserCAKeys /etc/ssh/openasy_access_ca.pub
AuthorizedPrincipalsFile /etc/ssh/openasy_access_principals/%u
RevokedKeys /etc/ssh/openasy_access_revoked.krl
OPENASY
sshd -t && (systemctl reload ssh 2>/dev/null || systemctl reload sshd)
```

The principals file is what keeps a certificate for one server from working on another: each server accepts only
its own `account@server`. sshd refuses every key when the revocation list is missing, so the commands fetch it
before sshd is told about it. The accounts must exist; Access does not create them. Distributions whose sshd_config
does not include `sshd_config.d` need the three lines in sshd_config itself.

Keys in `authorized_keys` keep working alongside: remove them, or nothing has changed. Keep one way in that does not
depend on Access, such as a console, for when Access is down.

## For the people who ask

Nothing to install: OpenSSH has done certificates since 2010. Ask under Requests; once someone else approves, paste
your public key on the request, save the certificate next to your key as `id_ed25519-cert.pub` (the name of your key
with `-cert.pub`), and `ssh deploy@web-1` as usual. The certificate stops working when the access ends; ask again
next time.

## Run

```bash
openssl rand -hex 32 > openasy-kek
docker compose up -d
docker compose logs access | grep 'no owner yet'
```

Open the link from the log once to create the owner account; there is no default password (ADR 0013). The UI and API
are on http://localhost:8080, the API reference at http://localhost:8080/api/docs/.

| Variable | Default | |
| --- | --- | --- |
| `PORT` | `8080` | HTTP port |
| `ACCESS_PUBLIC_URL` | `http://localhost:8080` | The address people open, with `https://` behind your TLS proxy; servers fetch the revocation list from it |
| `ACCESS_PENDING_HOURS` | `24` | A request nobody approves within this long is cancelled |
| `OPENASY_PRODUCTS` | | The install's other OpenAsy products, for the product switcher |
| `ACCESS_SECRETS_KEY_FILE` | `/run/secrets/openasy-kek` | 32-byte key-encryption key; Access does not start without it |
| `ACCESS_DB` | `/data/access.db` | SQLite file (WAL), on the `/data` volume |
| `ACCESS_METRICS_PORT` | | Serve `/metrics` on this port only (ADR 0026) |
| `ACCESS_HEADLESS` | `false` | `true` serves only the API |
| `ACCESS_PASSWORD_SIGN_IN`, `OPENASY_OIDC_*` | | Sign-in, as in every OpenAsy product ([@openasy/auth](https://github.com/openasy/auth)) |

`/metrics` has `openasy_access_requests_pending`, `openasy_access_grants_active`, `openasy_access_servers`,
`openasy_access_certificates_issued` and `openasy_access_refused`, the refused attempts of the last day, such as
approving one's own request.

Every event of the audit log is also written to stdout as JSON, for a SIEM to collect, and the whole log is exported as
CSV under Audit. The log keeps everything: rows are never changed or removed, by the API or by the database itself.

The container runs as non-root with a read-only root filesystem, no capabilities and `no-new-privileges`. Back up the
`/data` volume and `openasy-kek` together: without the key, the CA cannot be opened, and every server would have to
trust a new one.

## Roles

Viewers see everything and ask for access for themselves; editors also approve, deny and revoke what others asked for;
admins also keep the servers, and manage members and API tokens (ADR 0003). Invite the people who ask as viewers and
the team leads who approve as editors.

## Not yet

Access ends new logins at its time, and a revoked certificate within a minute, but a session already open on the
server stays open until it is closed: ending it, and recording sessions for review, need the session proxy, which is
planned with RDP and PostgreSQL and MySQL access. Per-server approvers and groups from Identity, approving from Slack,
automatic approval of low-risk access, certificates with port forwarding, rotating the CA and streaming the audit
log over syslog are planned too.

## Develop

```bash
npm install
npm test        # certificates and KRLs read back by ssh-keygen, requests, approvals, expiry, revocation, the audit log, and every API response against openapi.json
npm run dev     # the UI, with the API on :8080
docker build -t access:dev . && e2e/run.sh   # a real OpenSSH server trusts Access, and ssh logs in with its certificate
```

## Licence

AGPL-3.0 (ADR 0008).
