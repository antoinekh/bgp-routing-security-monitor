#!/usr/bin/env bash
# preflight.sh: check the lab is ready for the demo, in the normal (no leak)
# state. Prints one line per check and exits non-zero if any check fails.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

running "$(c raven)" || die "lab not deployed; run ./deploy.sh"
# Every check below handles its own failure; a grep that matches nothing
# must not end the script.
set +e +o pipefail

FAILED=0
pass() { printf '  PASS  %s\n' "$1"; }
fail() { printf '  FAIL  %s\n        %s\n' "$1" "$2"; FAILED=1; }

echo "preflight (RPKI_MODE=$RPKI_MODE)"

# 1. Every BGP session on every router is Established.
declare -A PEERS=([vantage]=2 [transit]=2 [cf-yvr]=1 [cf-gru]=1 [as7738]=2 [as53072]=2 [as262504]=2 [as1031]=2)
bad=""
for r in vantage transit cf-yvr cf-gru as7738 as53072 as262504 as1031; do
  sum=$(vtysh "$r" -c "show bgp ipv4 unicast summary json" 2>/dev/null || true)
  est=$(grep -o '"state":"Established"' <<<"$sum" | wc -l)
  [[ $est -eq ${PEERS[$r]} ]] || bad+=" $r($est/${PEERS[$r]})"
done
if [[ -z "$bad" ]]; then pass "BGP: all 7 sessions Established on all 8 routers"
else fail "BGP: sessions not Established" "routers (established/expected):$bad"; fi

# 2. BMP: vantage's two peers are up in raven status.
status=$(raven status 2>&1 || true)
up=$(grep -E '^\s+vantage\s+10\.47\.(1\.1|2\.2)\s+[0-9]+\s+up\b' <<<"$status" | wc -l)
if [[ $up -eq 2 ]]; then pass "BMP: vantage up in raven status, peers transit and as1031 up"
else fail "BMP: expected vantage peers 10.47.1.1 and 10.47.2.2 up in raven status" \
  "$(grep -A4 'BMP Peers' <<<"$status" | tr '\n' ' ')"; fi

# 3. RTR: session connected and VRPs loaded.
metrics=$(docker exec "$(c prometheus)" wget -qO- http://172.31.47.31:9595/metrics 2>/dev/null || true)
rtr=$(grep -E '^raven_rtr_session_state\{' <<<"$metrics" | awk '{print $2}' | head -1)
vrps=$(sed -n 's/^RPKI: \([0-9]*\) VRPs.*/\1/p' <<<"$status")
if [[ "$rtr" == 1 && "${vrps:-0}" -gt 0 ]]; then pass "RTR: session to Routinator connected, $vrps VRPs"
else fail "RTR: session or VRPs missing" "raven_rtr_session_state=${rtr:-absent} VRPs=${vrps:-unknown}"; fi

# 4. ASPA: AS53072 has a record and AS262504 is not among its providers.
aspa=$(raven aspa --asn 53072 --format json 2>&1 || true)
providers=$(tr -d ' \n' <<<"$aspa" | sed -n 's/.*"providers":\[\([0-9,]*\)\].*/\1/p')
if [[ -z "$providers" ]]; then fail "ASPA: no record for AS53072" "$aspa"
elif tr ',' '\n' <<<"$providers" | grep -qx 262504; then
  fail "ASPA: AS262504 is in AS53072's provider set" "providers: $providers"
else pass "ASPA: AS53072 => {$providers}, AS262504 not a provider"; fi

# 5. ROV: 1.1.1.0/24 from AS13335 is Valid.
routes=$(raven routes --prefix 1.1.1.0/24 --format json 2>&1 || true)
rov=$(tr -d ' \n' <<<"$routes" | grep -o '"origin_asn":13335[^}]*"rov":"[A-Za-z]*"' | sed 's/.*"rov":"//; s/"$//' | sort -u | tr '\n' ' ')
if [[ "$rov" == "Valid " ]]; then pass "ROV: 1.1.1.0/24 origin AS13335 is Valid"
else fail "ROV: 1.1.1.0/24 origin AS13335 not (only) Valid" "rov states seen: ${rov:-no route}"; fi

# 6. Probe: 1.1.1.1 answers from the YVR instance.
probe=$(docker exec "$(c probe)" bash /probe.sh 3 2>&1 || true)
if [[ $(grep -c 'rcode=NOERROR *nsid=yvr' <<<"$probe") -eq 3 ]]; then pass "probe: 3/3 queries answered with NSID yvr"
else fail "probe: expected NSID yvr on 3/3 queries" "$(tr '\n' '|' <<<"$probe")"; fi

# 7. netem on the leak link and on cf-yvr-transit.
for n in "${NETEM[@]}"; do
  read -r node ifname delay <<<"$n"
  qdisc=$(docker exec "$(c "$node")" tc qdisc show dev "$ifname" 2>&1)
  if grep -q "netem.*delay ${delay}" <<<"$qdisc"; then pass "netem: $delay on $node $ifname"
  else fail "netem: $delay not on $node $ifname" "$qdisc"; fi
done

if [[ $FAILED -ne 0 ]]; then echo "preflight FAILED"; exit 1; fi
echo "preflight OK"
