# shellcheck shell=bash
# Shared by the dns-oarc lab scripts. Source it; do not run it.

set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$LAB_DIR/../.." && pwd)"
LAB_NAME=dnsoarc
TOPO="$LAB_DIR/dnsoarc.clab.yaml"
RUNTIME="$LAB_DIR/runtime"

# Pinned images used outside the topology file (the topology pins its own).
KRILL_IMAGE=nlnetlabs/krill:v0.16.0
GO_IMAGE=golang:1.25.0-bookworm

# Krill admin token. Lab-only: Krill is reachable only on the lab's mgmt
# network and holds nothing but the two demo objects.
KRILL_TOKEN=dnsoarc-lab-token

if [[ ! -f "$LAB_DIR/.env" ]]; then
  echo "error: $LAB_DIR/.env not found; copy .env.example to .env first" >&2
  exit 1
fi
# shellcheck source=/dev/null
source "$LAB_DIR/.env"
RPKI_MODE="${RPKI_MODE:-lab}"
case "$RPKI_MODE" in
  lab | live) ;;
  *) echo "error: RPKI_MODE must be lab or live, not '$RPKI_MODE'" >&2; exit 1 ;;
esac
ROUTINATOR_CACHE_DIR="${ROUTINATOR_CACHE_DIR:-./runtime/routinator/repository}"
[[ "$ROUTINATOR_CACHE_DIR" = /* ]] || ROUTINATOR_CACHE_DIR="$LAB_DIR/${ROUTINATOR_CACHE_DIR#./}"
GRAFANA_PORT="${GRAFANA_PORT:-3047}"
GRAFANA_ADMIN_PASSWORD="${GRAFANA_ADMIN_PASSWORD:-}"

# Node container names.
c() { echo "clab-$LAB_NAME-$1"; }

# containerlab needs root unless the user is in clab_admins.
clab() {
  if [[ $EUID -eq 0 ]] || id -nG | tr ' ' '\n' | grep -qx clab_admins; then
    containerlab "$@"
  else
    sudo -E containerlab "$@"
  fi
}

running() { [[ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" == true ]]; }

vtysh() { local node=$1; shift; docker exec "$(c "$node")" vtysh "$@"; }
raven() { docker exec "$(c raven)" raven "$@"; }

# netem, applied by deploy.sh and checked by preflight.sh, as
# "node interface delay": the leak link (as53072 eth2 faces as262504) and
# the normal path's last hop (cf-yvr eth1 faces transit), so the probe sees
# a realistic few ms in the normal state.
NETEM=(
  "as53072 eth2 150ms"
  "cf-yvr eth1 5ms"
)

# as262504's session to as1031, soft-cleared by demo.sh leak/clean.
AS262504_TO_AS1031=10.47.10.2

log() { printf '[%s] %s\n' "$(basename "$0" .sh)" "$*"; }
die() { printf '[%s] error: %s\n' "$(basename "$0" .sh)" "$*" >&2; exit 1; }
