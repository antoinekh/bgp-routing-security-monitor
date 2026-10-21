#!/usr/bin/env bash
# deploy.sh: deploy the dnsoarc lab and apply netem (lib.sh NETEM): 150 ms on
# the as53072-as262504 link and 5 ms on cf-yvr-transit, left on permanently.
# Run ./bootstrap.sh first.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

[[ -x "$LAB_DIR/bin/raven" ]] || die "bin/raven missing; run ./bootstrap.sh"
[[ -s "$RUNTIME/krill/ca.pem" ]] || die "runtime/ not prepared; run ./bootstrap.sh"
[[ -n "$GRAFANA_ADMIN_PASSWORD" && "$GRAFANA_ADMIN_PASSWORD" != CHANGE_ME ]] \
  || die "set GRAFANA_ADMIN_PASSWORD in .env (it is empty or still the placeholder)"

ROUTINATOR_SERVE="server --rtr 0.0.0.0:3323 --http 0.0.0.0:8323"
case "$RPKI_MODE" in
  lab)
    [[ -s "$RUNTIME/routinator/tals/krill-testbed.tal" ]] || die "Krill TAL missing; run ./bootstrap.sh"
    # Only the Krill testbed TA. Its URIs are IP addresses on a non-default
    # port, which Routinator treats as dubious unless allowed.
    ROUTINATOR_CMD="--no-rir-tals --extra-tals-dir /tals --rrdp-root-cert /krill-ca.pem --allow-dubious-hosts --enable-aspa --repository-dir /repository $ROUTINATOR_SERVE --refresh 30"
    ;;
  live)
    # The five RIR TALs bundled with Routinator 0.15.2; Krill is not trusted.
    ROUTINATOR_CMD="--enable-aspa --repository-dir /repository $ROUTINATOR_SERVE"
    ;;
esac
export ROUTINATOR_CMD ROUTINATOR_CACHE_DIR GRAFANA_PORT GRAFANA_ADMIN_PASSWORD

# bootstrap.sh's temporary Krill must not share the data directory with the
# lab's.
docker rm -f dnsoarc-krill-bootstrap >/dev/null 2>&1 || true

log "deploying lab $LAB_NAME (RPKI_MODE=$RPKI_MODE)"
cd "$LAB_DIR"
clab deploy -t "$TOPO" --reconfigure

for n in "${NETEM[@]}"; do
  read -r node ifname delay <<<"$n"
  log "netem: $delay on $node $ifname"
  clab tools netem set -n "$(c "$node")" -i "$ifname" --delay "$delay"
done

# Wait for BGP to converge and RAVEN to hold vantage's routes; RPKI may take
# longer (a cold live-mode sync takes minutes), which preflight.sh checks.
log "waiting for BGP and BMP (up to 120s)"
for i in $(seq 1 120); do
  est=$(vtysh vantage -c "show bgp ipv4 unicast summary json" 2>/dev/null | grep -o '"state":"Established"' | wc -l || true)
  routes=$(raven routes --prefix 1.1.1.0/24 --format json 2>/dev/null | grep -c '"prefix"' || true)
  if [[ $est -eq 2 && $routes -ge 1 ]]; then log "BGP and BMP converged after ${i}s"; break; fi
  [[ $i -eq 120 ]] && log "not converged after 120s (vantage sessions up: $est, RAVEN routes for 1.1.1.0/24: $routes)"
  sleep 1
done

# In lab mode the RPKI is local and quick: Routinator may start before Krill
# serves and then picks it up on its next 30s refresh. Wait for RAVEN to see
# the ROA.
if [[ "$RPKI_MODE" == lab ]]; then
  log "waiting for RPKI: 1.1.1.0/24 ROV Valid in RAVEN (up to 120s)"
  for i in $(seq 1 120); do
    if raven routes --prefix 1.1.1.0/24 --format json 2>/dev/null | grep -q '"rov": "Valid"'; then
      log "RPKI ready after ${i}s"; break
    fi
    [[ $i -eq 120 ]] && log "RPKI not ready after 120s; ./preflight.sh will say what is missing"
    sleep 1
  done
fi

log "deployed. Grafana: http://localhost:$GRAFANA_PORT  (user admin, password GRAFANA_ADMIN_PASSWORD in .env)"
log "next: ./preflight.sh"
