#!/usr/bin/env bash
# Query the 1.1.1.1 anycast service and print one line per query:
#   <UTC time>  rcode=<RCODE>  nsid=<NSID>  latency=<ms>
# With a count, run that many queries and exit; without, loop forever
# (the probe container's main process).
count=${1:-0}
n=0
while :; do
  out=$(dig +nsid +tries=1 +time=1 @1.1.1.1 demo.oarc A 2>&1)
  ts=$(date -u +%H:%M:%S)
  rcode=$(sed -n 's/.*status: \([A-Z]*\).*/\1/p' <<<"$out")
  nsid=$(sed -n 's/.*NSID: .*("\(.*\)").*/\1/p' <<<"$out")
  ms=$(sed -n 's/.*Query time: \([0-9]*\) msec.*/\1/p' <<<"$out")
  lat=${ms:+${ms}ms}
  printf '%s  rcode=%-8s nsid=%-4s latency=%s\n' "$ts" "${rcode:-TIMEOUT}" "${nsid:--}" "${lat:--}"
  n=$((n + 1))
  [[ $count -gt 0 && $n -ge $count ]] && exit 0
  sleep 1
done
