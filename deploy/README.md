# Deploying freebeamer-relay

Runs the relay in Docker with persistent SQLite storage and an nginx TLS proxy.
Requires Docker Compose, Ansible, nginx, and certbot on the deployment host.

## Automated deploys

`.github/workflows/deploy.yml` deploys on every push to `main` (after tests
pass). All host-specific values are repository secrets
(Settings → Secrets and variables → Actions → Secrets):

| Secret | Contents |
| --- | --- |
| `RELAY_DEPLOY_SSH_KEY` | Private deploy key (Ed25519) |
| `RELAY_DEPLOY_HOST` | Host address |
| `RELAY_DEPLOY_KNOWN_HOSTS` | Pinned host key line, from `ssh-keyscan -t ed25519 <host>` checked against a fingerprint you trust |
| `RELAY_ADMIN_TOKEN` | `FREEBEAMER_RELAY_ADMIN_TOKEN` for the relay (24+ URL-safe characters) |
| `RELAY_DOMAIN` | Public hostname, e.g. `telemetry.example.net` |
| `RELAY_CERTBOT_EMAIL` | Let's Encrypt contact address |

The workflow SSHes in as `source` and sends the token, domain and email as
`KEY=VALUE` lines on stdin. On the host the deploy key is restricted to
[`forced-command.sh`](forced-command.sh), which resets the checkout to
`origin/main` and runs [`remote-deploy.sh`](remote-deploy.sh). That script
accepts only those three keys, validates them, rewrites `deploy/.env` (mode
0600) and runs `ansible-playbook deploy.yml`. Rotating the token or moving to
a new host is a secrets change; the host keeps no other deploy configuration.

One-time host setup: clone this repository to
`/home/source/studio/build_repositories/freebeamer/relay` (or set
`RELAY_CHECKOUT` in the forced command), install `forced-command.sh` as
`~/bin/freebeamer-relay-deploy.sh`, and add the deploy public key to
`~/.ssh/authorized_keys` with the `command=` restriction shown in that file.
The `source` user needs passwordless sudo for the playbook's `become` steps.

## Manual first-time setup

1. `cp .env.example .env` and set `FREEBEAMER_RELAY_ADMIN_TOKEN` to a
   real secret (the relay refuses to start without one — see
   `cmd/freebeamer-relay/command_serve.go`). `.env` is gitignored;
   never commit it.
2. Point a real DNS name at this server and pass it as `domain`:

   ```sh
   ansible-playbook -i localhost, -c local deploy.yml -e domain=relay.yourdomain.tld -e certbot_email=you@example.com
   ```

   The example deploys locally; use your own inventory for a remote host.

This builds the image, starts the container (SQLite persisted in the
`relay-data` named volume), writes and enables the nginx site, and
requests a cert via certbot on first run (idempotent — skipped if the
cert already exists).

## After deploying

Mint a pairing link from inside the running container — a device
redeems it itself (`POST /v1/pair`, generating its own Ed25519 keypair)
rather than being handed a permanent key:

```sh
docker compose exec freebeamer-relay /app/freebeamer-relay client pairing-link create \
  --name "<client name>" --db /data/freebeamer-relay.sqlite --public-url https://<domain>
```

This prints a `freebeamer://connect` link (single-use, 15 minutes by
default) to share with the device. See the relay v0 plan's Auth section
for the full pairing/challenge/session flow.

Point the mobile app's "Relay upload URL" at
`https://<domain>/v1/telemetry` and the desktop app's live feed at
`wss://<domain>/v1/live` (the whole garage; add `?client_id=...` to limit
it to one client) — both routes are served by the
same container; the nginx template proxies everything (including the
WebSocket upgrade) to it. See [the relay design](https://github.com/freebeamer/core/blob/main/docs/freebeamer-relay-v0-plan.md) for
the full API.

## Redeploying after a code change

Re-run the same `ansible-playbook` command — `docker compose up -d
--build` picks up new commits already pulled into this checkout;
nginx/certbot steps are idempotent and no-op if nothing changed.
