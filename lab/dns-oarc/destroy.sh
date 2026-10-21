#!/usr/bin/env bash
# destroy.sh: tear down the dnsoarc lab. runtime/ (Krill data, Routinator
# cache, TAL) and bin/ are kept, so the next deploy starts warm.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# The topology needs these set to parse; destroy does not use their values.
export ROUTINATOR_CMD=server ROUTINATOR_CACHE_DIR GRAFANA_PORT GRAFANA_ADMIN_PASSWORD=unused
cd "$LAB_DIR"
clab destroy -t "$TOPO" --cleanup
docker rm -f dnsoarc-krill-bootstrap >/dev/null 2>&1 || true
log "destroyed lab $LAB_NAME"
