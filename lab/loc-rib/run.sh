#!/bin/bash
# Loc-RIB (RFC 9069) lab: deploy, check and destroy.

set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$LAB_DIR/../.." && pwd)"
TOPOLOGY="$LAB_DIR/loc-rib.clab.yml"
API="http://172.31.90.10:11020/api/v1"
METRICS="http://172.31.90.10:9595/metrics"
# The monitored routers, as RAVEN knows them: the source address of each
# one's BMP session (its management address).
RR1="172.31.90.21"
RR2="172.31.90.22"
# rr1's router-id, and the address rr2 peers with.
RR1_ID="10.0.12.1"
TIMEOUT="${TIMEOUT:-60}"
# rr1's BMP target, exactly as FRR shows it in its running-config (the
# commands are the same; the block is entered under "router bgp 65000").
RR1_BMP=(
  "bmp targets raven"
  "bmp monitor ipv4 unicast loc-rib"
  "bmp connect 172.31.90.10 port 11019 min-retry 1000 max-retry 5000"
)

usage() {
  cat <<EOF
Usage: $(basename "$0") <command>

Loc-RIB lab: rr1 ($RR1) exports its Loc-RIB to RAVEN, rr2 ($RR2) exports
the pre-policy Adj-RIB-In of its iBGP session to rr1 ($RR1_ID).

Commands:
  up       Build a static RAVEN binary and deploy the lab
  test     Run the live checks against the deployed lab
  reset    Restore the routers' initial config (BMP target on rr1, rr2's
           session to rr1, ext1's prefixes) without redeploying, and wait
           for RAVEN to see rr1's Loc-RIB again
  down     Destroy the lab
  all      up, test, then down (the lab stays up if a check fails)
  -h, --help
           Show this help

Every wait gives up after TIMEOUT seconds with a FAIL and a hint. A test run
that is interrupted or fails puts back any router config it changed.

Environment:
  TIMEOUT  Seconds to wait for each check to converge (default: 60)

Examples:
  $(basename "$0") all
  $(basename "$0") up && $(basename "$0") test
  $(basename "$0") reset
EOF
}

if [[ -t 1 ]]; then
  BOLD=$'\e[1;36m' GREEN=$'\e[32m' RED=$'\e[31m' DIM=$'\e[2m' RESET=$'\e[0m'
else
  BOLD="" GREEN="" RED="" DIM="" RESET=""
fi

step() {
  printf '\n%s== %s%s\n' "$BOLD" "$1" "$RESET"
}

fail() {
  printf '  %sFAIL%s  %s\n' "$RED" "$RESET" "$1" >&2
  shift
  local line
  for line in "$@"; do
    printf '        %s\n' "$line" >&2
  done
}

# vtysh <node> <command...>: run vtysh commands on a router. Fails loudly,
# with the router's output, if vtysh exits non-zero or prints an error or
# warning ("% ..."): vtysh -c exits 0 on a warning, so its status alone does
# not show a rejected command.
vtysh() {
  local node=$1
  shift
  local args=() line out rc=0
  for line in "$@"; do
    args+=(-c "$line")
  done
  out="$(timeout 30 docker exec "clab-loc-rib-$node" vtysh "${args[@]}" 2>&1)" || rc=$?
  if ((rc != 0)) || grep -qE '^[[:space:]]*(line [0-9]+: )?%' <<<"$out"; then
    fail "vtysh on $node failed (exit $rc): $*" "${out:-(no output)}"
    return 1
  fi
}

# running_config <node>: the router's running-config.
running_config() {
  timeout 30 docker exec "clab-loc-rib-$1" vtysh -c "show running-config" 2>&1
}

# config_has <node> <present|absent> <line...>: check lines (leading spaces
# ignored) are in, or not in, the router's running-config.
config_has() {
  local node=$1 mode=$2 cfg line ok=0
  shift 2
  if ! cfg="$(running_config "$node")"; then
    fail "cannot read $node's running-config" "$cfg"
    return 1
  fi
  cfg="$(sed 's/^[[:space:]]*//; s/[[:space:]]*$//' <<<"$cfg")"
  for line in "$@"; do
    if grep -qxF "$line" <<<"$cfg"; then
      [[ $mode == absent ]] && { fail "$node's running-config still has: $line"; ok=1; }
    else
      [[ $mode == present ]] && { fail "$node's running-config lacks: $line" \
        "hint: docker exec clab-loc-rib-$node vtysh -c 'show running-config'"; ok=1; }
    fi
  done
  return $ok
}

# ── Router config the checks change, and how to put it back ──────────────
# Each change marks its router dirty first; cleanup restores what is dirty.

DIRTY_EXT1=0 DIRTY_RR2=0 DIRTY_RR1=0

restore_ext1() {
  vtysh ext1 "configure terminal" "router bgp 64510" "address-family ipv4 unicast" \
    "network 192.0.2.0/24" "network 203.0.113.0/24" &&
    config_has ext1 present "network 192.0.2.0/24" "network 203.0.113.0/24" &&
    DIRTY_EXT1=0
}

restore_rr2() {
  vtysh rr2 "configure terminal" "router bgp 65000" "no neighbor $RR1_ID shutdown" &&
    config_has rr2 absent "neighbor $RR1_ID shutdown" &&
    DIRTY_RR2=0
}

restore_rr1_bmp() {
  vtysh rr1 "configure terminal" "router bgp 65000" "${RR1_BMP[@]}" "exit" &&
    config_has rr1 present "${RR1_BMP[@]}" &&
    DIRTY_RR1=0
}

# cleanup restores every router a check left changed. It runs on exit,
# however the test ends (a failed check, an error, Ctrl-C).
cleanup() {
  local rc=$? failed=0
  trap - EXIT INT TERM
  set +e
  if ((DIRTY_EXT1 + DIRTY_RR2 + DIRTY_RR1 > 0)); then
    step "Restoring the router config the checks changed"
    ((DIRTY_EXT1)) && { restore_ext1 || failed=1; }
    ((DIRTY_RR2)) && { restore_rr2 || failed=1; }
    ((DIRTY_RR1)) && { restore_rr1_bmp || failed=1; }
    if ((failed)); then
      fail "could not restore the lab's config" "hint: $(basename "$0") reset, or redeploy: $(basename "$0") down && $(basename "$0") up"
    else
      printf '  %sok%s    config restored\n' "$GREEN" "$RESET"
    fi
  fi
  exit "$rc"
}

# ── Queries. Every call is bounded, so no wait can hang. ─────────────────

api() {
  curl -sf --noproxy '*' --max-time 5 "$API/$1"
}

# routes <router> [rib]: a router's routes as "prefix as_path posture" lines,
# sorted. Without rib, the API's default view (adj-rib-in-pre and loc-rib).
routes() {
  local router=$1 rib=${2:-}
  local q="router=$router"
  [[ -n $rib ]] && q+="&rib=$rib"
  api "routes?$q" | jq -r '.[] | "\(.prefix) \(.as_path | map(tostring) | join(",")) \(.posture)"' | sort
}

# default_view <prefix>: the RIB and router of each route to prefix that the
# API lists without a rib parameter, sorted.
default_view() {
  api "routes?prefix=$1" | jq -r '.[] | "\(.rib) \(.router)"' | sort
}

# rr1_peers: rr1's Loc-RIB and its route count, and how many of its other
# peers have routes. FRR 10.7.1 also sends Peer Up for rr1's BGP neighbors,
# though its target monitors the Loc-RIB only; they must have no routes.
rr1_peers() {
  api "peers?router=$RR1" | jq -r '
    ([.[] | select(.peer_type == "loc-rib") | "loc-rib \(.addr) routes=\(.route_count)"] | sort | .[]),
    "other peers with routes: \([.[] | select(.peer_type != "loc-rib" and .route_count > 0)] | length)"'
}

# peers <router>: a router's BMP peers as "peer_type addr" lines, sorted.
peers() {
  api "peers?router=$1" | jq -r '.[] | "\(.peer_type) \(.addr)"' | sort
}

# loc_rib_state: raven_bmp_peer_state of rr1's Loc-RIB (peer 0.0.0.0).
loc_rib_state() {
  curl -sf --noproxy '*' --max-time 5 "$METRICS" |
    awk -v r="router_addr=\"$RR1\"" '/^raven_bmp_peer_state\{/ && index($0, r) && index($0, "peer=\"0.0.0.0\"") { print $NF }'
}

# status_header: raven status's route table line, without the count.
status_header() {
  timeout 15 docker exec clab-loc-rib-raven raven --address 127.0.0.1:11020 status |
    grep '^Route Table:' | sed 's/^Route Table: [0-9]* //'
}

# expect <description> <expected output> <hint> <command...>: retry until the
# command prints the expected output, for at most TIMEOUT seconds, printing
# progress every 5 seconds. On timeout: FAIL, what it last got, and the hint.
expect() {
  local desc=$1 want=$2 hint=$3
  shift 3
  local got="" start=$SECONDS next=$((SECONDS + 5))
  while :; do
    got="$("$@" 2>/dev/null || true)"
    if [[ $got == "$want" ]]; then
      printf '  %sok%s    %s %s(%ds)%s\n' "$GREEN" "$RESET" "$desc" "$DIM" $((SECONDS - start)) "$RESET"
      return 0
    fi
    if ((SECONDS - start >= TIMEOUT)); then
      fail "$desc (after ${TIMEOUT}s)" "want: ${want//$'\n'/ | }" "got:  ${got//$'\n'/ | }" "hint: $hint"
      return 1
    fi
    if ((SECONDS >= next)); then
      printf '  %s..    %s: waiting, %ds of %ds; got: %s%s\n' "$DIM" "$desc" $((SECONDS - start)) "$TIMEOUT" \
        "${got//$'\n'/ | }" "$RESET"
      next=$((SECONDS + 5))
    fi
    sleep 1
  done
}

HINT_RR1_BMP="is rr1 connected? docker exec clab-loc-rib-rr1 vtysh -c 'show bmp'; RAVEN's log: docker logs clab-loc-rib-raven"
HINT_RR2="docker exec clab-loc-rib-rr2 vtysh -c 'show bgp summary' -c 'show bmp'"
HINT_EXT1="docker exec clab-loc-rib-rr1 vtysh -c 'show bgp ipv4 unicast'"

LOC_RIB="192.0.2.0/24 64510 unverified
198.51.100.0/24 64510 origin-invalid
203.0.113.0/24 64510 origin-only"
PRE_POLICY="$LOC_RIB"

cmd_up() {
  step "Build a static RAVEN binary"
  (cd "$REPO_DIR" && CGO_ENABLED=0 go build -o "$LAB_DIR/bin/raven" ./cmd/raven)

  step "Deploy the lab"
  containerlab deploy -t "$TOPOLOGY" --reconfigure
}

cmd_reset() {
  local failed=0
  step "Restore the routers' initial config"
  restore_ext1 || failed=1
  restore_rr2 || failed=1
  restore_rr1_bmp || failed=1
  config_has rr2 present "bmp targets raven" "bmp monitor ipv4 unicast pre-policy" || failed=1
  ((failed)) && return 1
  printf '  %sok%s    config restored\n' "$GREEN" "$RESET"

  step "Wait for RAVEN"
  expect "rr1's Loc-RIB is back" "$LOC_RIB" "$HINT_RR1_BMP" routes "$RR1" loc-rib || failed=1
  expect "rr2's pre-policy routes are back" "$PRE_POLICY" "$HINT_RR2" routes "$RR2" adj-rib-in-pre || failed=1
  return $failed
}

cmd_test() {
  local failed=0
  trap cleanup EXIT
  trap 'exit 130' INT TERM

  step "Preflight: the routers have their initial config"
  if ! config_has rr1 present "${RR1_BMP[@]}" ||
    ! config_has rr2 present "bmp targets raven" "neighbor $RR1_ID remote-as 65000" ||
    ! config_has rr2 absent "neighbor $RR1_ID shutdown"; then
    fail "the lab is not in its initial state" "hint: $(basename "$0") reset"
    return 1
  fi
  printf '  %sok%s    initial config present\n' "$GREEN" "$RESET"

  step "Initial state"
  expect "rr1's Loc-RIB has its routes; rr1's other peers (FRR 10.7.1 sends their Peer Up) have none" \
    "loc-rib 0.0.0.0 routes=3
other peers with routes: 0" "$HINT_RR1_BMP" rr1_peers || failed=1
  expect "rr2 has one peer, rr1 at $RR1_ID" "global $RR1_ID" "$HINT_RR2" peers "$RR2" || failed=1
  expect "Loc-RIB: one best route per prefix, 10.99.0.0/24 rejected by rr1's import policy" \
    "$LOC_RIB" "$HINT_RR1_BMP" routes "$RR1" loc-rib || failed=1
  expect "adj-rib-in-pre: rr2's Adj-RIB-In from rr1, stored apart" \
    "$PRE_POLICY" "$HINT_RR2" routes "$RR2" adj-rib-in-pre || failed=1
  expect "pre-policy is an alias of adj-rib-in-pre" "$PRE_POLICY" "$HINT_RR2" routes "$RR2" pre-policy || failed=1
  expect "the default view (no rib) lists rr1's Loc-RIB and rr2's pre-policy route" \
    "adj-rib-in-pre $RR2
loc-rib $RR1" "$HINT_RR1_BMP" default_view 198.51.100.0/24 || failed=1
  expect "a router that sends only its Loc-RIB has routes in the default view" \
    "$LOC_RIB" "$HINT_RR1_BMP" routes "$RR1" || failed=1
  expect "raven status names the RIBs of its default view" \
    "routes in the default view (adj-rib-in-pre + loc-rib)" "docker logs clab-loc-rib-raven" status_header || failed=1
  expect "raven_bmp_peer_state of rr1's Loc-RIB is 1" "1" "curl -s $METRICS | grep raven_bmp_peer_state" loc_rib_state || failed=1

  step "ext1 withdraws 192.0.2.0/24 and 203.0.113.0/24"
  DIRTY_EXT1=1
  vtysh ext1 "configure terminal" "router bgp 64510" "address-family ipv4 unicast" \
    "no network 192.0.2.0/24" "no network 203.0.113.0/24" || return 1
  expect "Loc-RIB: 192.0.2.0/24 is withdrawn, 203.0.113.0/24 moves to the ext2 path" \
    "198.51.100.0/24 64510 origin-invalid
203.0.113.0/24 64520,64510 origin-only" "$HINT_EXT1" routes "$RR1" loc-rib || failed=1
  restore_ext1 || return 1
  expect "Loc-RIB: back to the ext1 paths" "$LOC_RIB" "$HINT_EXT1" routes "$RR1" loc-rib || failed=1

  step "Peer down on rr2 for $RR1_ID"
  DIRTY_RR2=1
  vtysh rr2 "configure terminal" "router bgp 65000" "neighbor $RR1_ID shutdown" || return 1
  expect "adj-rib-in-pre: rr2's routes from $RR1_ID are withdrawn" "" "$HINT_RR2" routes "$RR2" adj-rib-in-pre || failed=1
  expect "Loc-RIB: rr1's routes stay" "$LOC_RIB" "$HINT_RR1_BMP" routes "$RR1" loc-rib || failed=1
  restore_rr2 || return 1
  expect "adj-rib-in-pre: rr2's routes are back" "$PRE_POLICY" "$HINT_RR2" routes "$RR2" adj-rib-in-pre || failed=1

  step "End of rr1's BMP session"
  DIRTY_RR1=1
  vtysh rr1 "configure terminal" "router bgp 65000" "no bmp targets raven" || return 1
  config_has rr1 absent "bmp targets raven" || return 1
  expect "Loc-RIB: rr1's routes are withdrawn" "" "docker logs clab-loc-rib-raven | grep 'session ended'" \
    routes "$RR1" loc-rib || failed=1
  expect "adj-rib-in-pre: rr2's routes stay" "$PRE_POLICY" "$HINT_RR2" routes "$RR2" adj-rib-in-pre || failed=1
  expect "raven_bmp_peer_state of rr1's Loc-RIB goes to 0" "0" "curl -s $METRICS | grep raven_bmp_peer_state" \
    loc_rib_state || failed=1
  restore_rr1_bmp || return 1
  printf '  %sok%s    rr1 BMP target back in its running-config\n' "$GREEN" "$RESET"
  expect "Loc-RIB: rr1 reconnects and its routes are back" "$LOC_RIB" "$HINT_RR1_BMP" routes "$RR1" loc-rib || failed=1
  expect "raven_bmp_peer_state of rr1's Loc-RIB is back to 1" "1" "curl -s $METRICS | grep raven_bmp_peer_state" \
    loc_rib_state || failed=1

  step "Result"
  if ((failed)); then
    printf '%sSome checks failed.%s\n' "$RED" "$RESET"
    return 1
  fi
  printf '%sAll checks passed.%s\n' "$GREEN" "$RESET"
}

cmd_down() {
  step "Destroy the lab"
  containerlab destroy -t "$TOPOLOGY" --cleanup
}

case "${1:-}" in
  up) cmd_up ;;
  test) cmd_test ;;
  reset) cmd_reset ;;
  down) cmd_down ;;
  all) cmd_up && cmd_test && cmd_down ;;
  -h | --help) usage ;;
  *)
    usage >&2
    exit 2
    ;;
esac
