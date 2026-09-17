# Deploying freebeamer-relay

Runs the relay in Docker with persistent SQLite storage and an nginx TLS proxy.
Requires Docker Compose, Ansible, nginx, and certbot on the deployment host.

## Automated deploys

`.github/workflows/deploy.yml` deploys on every push to `main` (after
tests pass): it SSHes into the deployment host with a dedicated key that
is restricted server-side to a forced command
(`/home/source/bin/freebeamer-relay-deploy.sh`, outside this repo), which
pulls `main` into a persistent checkout and re-runs the same
`ansible-playbook deploy.yml` command described below. First run
bootstraps `deploy/.env` (a random `FREEBEAMER_RELAY_ADMIN_TOKEN`) and
the nginx/certbot setup; later runs just rebuild the container, since
those steps are idempotent and no-op when nothing changed. The relay is
live at `https://telemetry.pactsign.net` (see the mobile README for why
this is a temporary hostname).

The SSH private key lives only in the `RELAY_DEPLOY_SSH_KEY` repository
secret. Rotate it by generating a new keypair, replacing the
`authorized_keys` entry on the host, and updating the secret.

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
`wss://<domain>/v1/live?client_id=...` — both routes are served by the
same container; the nginx template proxies everything (including the
WebSocket upgrade) to it. See [the relay design](https://github.com/freebeamer/core/blob/main/docs/freebeamer-relay-v0-plan.md) for
the full API.

## Redeploying after a code change

Re-run the same `ansible-playbook` command — `docker compose up -d
--build` picks up new commits already pulled into this checkout;
nginx/certbot steps are idempotent and no-op if nothing changed.
