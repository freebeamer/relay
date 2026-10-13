#!/bin/sh
# Install once on the deployment host as the deploy key's forced command:
#
#   install -m 0755 deploy/forced-command.sh ~/bin/freebeamer-relay-deploy.sh
#
# and in ~/.ssh/authorized_keys:
#
#   command="/home/source/bin/freebeamer-relay-deploy.sh",no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty ssh-ed25519 AAAA... freebeamer-relay-deploy
#
# It only updates the checkout to origin/main and hands stdin (the workflow's
# secret payload) to the repo's deploy/remote-deploy.sh, so deploy changes
# never require editing the host again. Set RELAY_CHECKOUT if the checkout
# lives somewhere else.
set -eu
checkout=${RELAY_CHECKOUT:-/home/source/studio/build_repositories/freebeamer/relay}
cd "$checkout"
git fetch --quiet origin main
git reset --quiet --hard origin/main
exec deploy/remote-deploy.sh
