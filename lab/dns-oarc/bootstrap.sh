#!/usr/bin/env bash
# bootstrap.sh: build RAVEN, prepare runtime/, and in RPKI_MODE=lab set up
# Krill (testbed TA + CA), issue exactly the demo's ROA and ASPA, and install
# the Krill TAL for Routinator. Idempotent: safe to run again at any time.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

command -v docker >/dev/null || die "docker not found"
command -v containerlab >/dev/null || die "containerlab not found"
log "RPKI_MODE=$RPKI_MODE"

# ── 1. RAVEN binary: static linux/amd64 ───────────────────────────────────
GO=$(command -v go || true)
[[ -z "$GO" && -x /usr/local/go/bin/go ]] && GO=/usr/local/go/bin/go
VERSION=$(git -C "$REPO_DIR" describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS="-s -w -X github.com/nokia/bgp-routing-security-monitor/internal/buildinfo.Version=$VERSION"
mkdir -p "$LAB_DIR/bin"
if [[ -n "$GO" ]]; then
  log "building bin/raven with $($GO version | awk '{print $3}')"
  (cd "$REPO_DIR" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    "$GO" build -trimpath -ldflags "$LDFLAGS" -o "$LAB_DIR/bin/raven" ./cmd/raven)
else
  log "no Go toolchain on PATH; building bin/raven in $GO_IMAGE"
  docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -e CGO_ENABLED=0 -e GOOS=linux -e GOARCH=amd64 \
    -e GOFLAGS=-buildvcs=false -v "$REPO_DIR:/src" -w /src "$GO_IMAGE" \
    go build -trimpath -ldflags "$LDFLAGS" -o lab/dns-oarc/bin/raven ./cmd/raven
fi
log "bin/raven: $(file -b "$LAB_DIR/bin/raven" 2>/dev/null | cut -d, -f1-2 || echo built)"

# ── 2. Runtime directories (gitignored) ───────────────────────────────────
# Routinator runs as uid 1012 and must write its cache; the other dirs are
# written by containers running as root.
mkdir -p "$RUNTIME/krill/data/ssl" "$RUNTIME/krill/data/repo/rsync/current" "$RUNTIME/krill/ta" \
  "$RUNTIME/routinator/tals" "$ROUTINATOR_CACHE_DIR" "$RUNTIME/grafana/dashboards"
chmod 0777 "$ROUTINATOR_CACHE_DIR"

# Grafana: the RAVEN dashboard with its datasource input bound to the
# provisioned Prometheus. lab/grafana-dashboard.json itself is not touched.
sed 's/\${DS_PROMETHEUS}/dnsoarc-prometheus/g' "$REPO_DIR/lab/grafana-dashboard.json" \
  > "$RUNTIME/grafana/dashboards/raven.json"
log "grafana dashboard provisioned from lab/grafana-dashboard.json"

# Krill's HTTPS certificate: a leaf for its mgmt address, signed by a lab CA
# that Routinator trusts for RRDP (--rrdp-root-cert). Routinator's TLS stack
# does not accept a self-signed CA certificate as the server's own.
if [[ ! -s "$RUNTIME/krill/ca.pem" || ! -s "$RUNTIME/krill/data/ssl/cert.pem" ]]; then
  docker run --rm --entrypoint sh -v "$RUNTIME/krill:/k" "$KRILL_IMAGE" -c '
    set -e; cd /k
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=dnsoarc lab CA" \
      -keyout ca.key -out ca.pem
    openssl req -newkey rsa:2048 -nodes -subj /CN=krill -keyout data/ssl/key.pem -out krill.csr
    printf "%s\n" "basicConstraints=critical,CA:FALSE" \
      "keyUsage=critical,digitalSignature,keyEncipherment" "extendedKeyUsage=serverAuth" \
      "subjectAltName=IP:172.31.47.33,IP:127.0.0.1,DNS:localhost" > leaf.ext
    openssl x509 -req -in krill.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 3650 \
      -extfile leaf.ext -out data/ssl/cert.pem
    rm -f krill.csr leaf.ext ca.srl' 2>/dev/null
  log "generated lab CA and Krill TLS certificate"
fi

if [[ "$RPKI_MODE" == live ]]; then
  # Nothing may trust Krill in live mode.
  rm -f "$RUNTIME/routinator/tals/"*.tal
  log "live mode: Routinator will use the five bundled RIR TALs; Krill TAL removed"
  log "done. Next: ./deploy.sh"
  exit 0
fi

# ── 3. Lab mode: Krill objects and TAL ────────────────────────────────────
# Use the lab's Krill if it is deployed; otherwise run it briefly on the same
# data directory and config.
KRILL=$(c krill)
TEMP=""
if ! running "$KRILL"; then
  KRILL=dnsoarc-krill-bootstrap
  TEMP=$KRILL
  docker rm -f "$KRILL" >/dev/null 2>&1 || true
  docker run -d --name "$KRILL" -v "$RUNTIME/krill/data:/var/krill/data" \
    -v "$LAB_DIR/configs/krill/krill.conf:/etc/krill.conf:ro" "$KRILL_IMAGE" krill -c /etc/krill.conf >/dev/null
  # Stop it gracefully: killed mid-publication, Krill keeps believing the
  # objects are published and does not publish them again on restart.
  trap 'docker stop -t 20 "$TEMP" >/dev/null 2>&1; docker rm -f "$TEMP" >/dev/null 2>&1 || true' EXIT
  log "started temporary Krill ($KRILL)"
fi
krillc() {
  docker exec -e KRILL_CLI_TOKEN="$KRILL_TOKEN" -e KRILL_CLI_SERVER=https://127.0.0.1:3000/ "$KRILL" krillc "$@"
}
for i in $(seq 1 60); do
  krillc list 2>/dev/null | grep -qx testbed && break
  [[ $i -eq 60 ]] && { docker logs "$KRILL" 2>&1 | tail -20; die "Krill testbed CA not ready after 60s"; }
  sleep 1
done
log "Krill testbed CA ready"

# Reconcile to exactly these objects. They mirror the real records: the
# 1.1.1.0/24 ROA Cloudflare publishes, and AS53072's real ASPA provider set.
WANT_ROA="1.1.1.0/24-24 => 13335"
WANT_ASPA="AS53072 => AS16735, AS23106, AS270735"
# krillc prints one object per line, "<definition>" optionally followed by
# " # comment"; an empty CA prints nothing.
roas() { krillc roas list --ca testbed | sed 's/ *#.*//' | grep '=>' || true; }
aspas() { krillc aspas list --ca testbed | grep '=>' || true; }
roas | while read -r roa; do
  [[ "$roa" == "$WANT_ROA" ]] || { krillc roas update --ca testbed --remove "$roa" >/dev/null; log "removed ROA $roa"; }
done
if grep -qxF "$WANT_ROA" <<<"$(roas)"; then
  log "ROA present: $WANT_ROA"
else
  krillc roas update --ca testbed --add "$WANT_ROA" >/dev/null
  log "issued ROA: $WANT_ROA"
fi
aspas | while read -r aspa; do
  cust=${aspa%% *}
  [[ "$cust" == AS53072 ]] || { krillc aspas remove --ca testbed --customer "$cust" >/dev/null; log "removed ASPA $aspa"; }
done
if grep -qxF "$WANT_ASPA" <<<"$(aspas)"; then
  log "ASPA present: $WANT_ASPA"
else
  krillc aspas add --ca testbed --aspa "53072 => 16735, 23106, 270735" >/dev/null
  log "issued ASPA: $WANT_ASPA"
fi
log "Krill testbed CA now holds:"
roas | sed 's/^/    ROA  /'
aspas | sed 's/^/    ASPA /'

# Krill publishes asynchronously. Wait until the testbed CA's ROA and ASPA
# are in the repository before going on (and before stopping Krill).
PUB="$RUNTIME/krill/data/repo/rsync/current/testbed/0"
for i in $(seq 1 60); do
  if [[ -n "$(find "$PUB" -name '*.roa' 2>/dev/null)" && -s "$PUB/AS53072.asa" ]]; then break; fi
  [[ $i -eq 60 ]] && die "Krill has not published the testbed CA's objects after 60s"
  sleep 1
done
log "published in Krill's repository: $(cd "$PUB" && ls | tr '\n' ' ')"

# The TAL for Routinator, and the TA certificate for the rsync sidecar.
docker exec "$KRILL" wget -qO- --no-check-certificate https://127.0.0.1:3000/ta/ta.tal \
  > "$RUNTIME/routinator/tals/krill-testbed.tal"
docker exec "$KRILL" wget -qO- --no-check-certificate https://127.0.0.1:3000/ta/ta.cer \
  > "$RUNTIME/krill/ta/ta.cer"
grep -q '^https://172.31.47.33:3000/ta/ta.cer$' "$RUNTIME/routinator/tals/krill-testbed.tal" \
  || die "unexpected Krill TAL: $(head -2 "$RUNTIME/routinator/tals/krill-testbed.tal")"
log "installed TAL runtime/routinator/tals/krill-testbed.tal"
log "done. Next: ./deploy.sh"
