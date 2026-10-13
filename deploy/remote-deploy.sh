#!/usr/bin/env bash
# Server side of the GitHub Actions deploy. The deploy key's forced command
# (deploy/forced-command.sh, installed once on the host) updates this checkout
# and then runs this script with the workflow's payload on stdin.
#
# The payload is KEY=VALUE lines built from repository secrets. Only the keys
# below are accepted; anything else aborts the deploy. Nothing deploy-specific
# is stored on the host outside deploy/.env, which this script rewrites.
set -euo pipefail
cd "$(dirname "$0")"

declare -A payload=()
while IFS= read -r line || [ -n "$line" ]; do
  [ -z "$line" ] && continue
  key=${line%%=*}
  value=${line#*=}
  case "$key" in
    FREEBEAMER_RELAY_ADMIN_TOKEN | RELAY_DOMAIN | RELAY_CERTBOT_EMAIL) payload[$key]=$value ;;
    *)
      echo "deploy: unexpected payload key: $key" >&2
      exit 1
      ;;
  esac
done

require() {
  local key=$1 pattern=$2
  if [[ -z ${payload[$key]:-} ]]; then
    echo "deploy: $key is missing from the payload; set its repository secret" >&2
    exit 1
  fi
  if [[ ! ${payload[$key]} =~ $pattern ]]; then
    echo "deploy: $key has an invalid format" >&2
    exit 1
  fi
}
require FREEBEAMER_RELAY_ADMIN_TOKEN '^[A-Za-z0-9._~+/=-]{24,}$'
require RELAY_DOMAIN '^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$'
require RELAY_CERTBOT_EMAIL '^[^[:space:]@]+@[A-Za-z0-9.-]+$'

umask 077
env_file=$(mktemp .env.XXXXXX)
printf 'FREEBEAMER_RELAY_ADMIN_TOKEN=%s\n' "${payload[FREEBEAMER_RELAY_ADMIN_TOKEN]}" >"$env_file"
mv "$env_file" .env

exec ansible-playbook -i localhost, -c local deploy.yml \
  -e "domain=${payload[RELAY_DOMAIN]}" \
  -e "certbot_email=${payload[RELAY_CERTBOT_EMAIL]}"
