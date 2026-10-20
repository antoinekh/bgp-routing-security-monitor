#!/usr/bin/env bash
# demo.sh <cmd>: the DNS-OARC 47 demo.
#   status         raven status
#   probe [N]      the probe's queries to 1.1.1.1: follow its log, or run N
#                  fresh queries and exit
#   watch          raven watch, path-suspect routes only (Ctrl+C to stop)
#   routes         raven routes for 1.1.1.0/24, wide format
#   leak           as262504 stops denying as53072's routes toward as1031
#   clean          restore the deny
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() { sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
running "$(c raven)" || die "lab not deployed; run ./deploy.sh"

# Interactive commands get a TTY so Ctrl+C reaches them.
TTY=()
[[ -t 0 && -t 1 ]] && TTY=(-it)

softclear() {
  vtysh as262504 -c "clear bgp ipv4 unicast $AS262504_TO_AS1031 soft out"
}

case "${1:-}" in
  status) raven status ;;
  probe)
    if [[ -n "${2:-}" ]]; then
      docker exec "$(c probe)" bash /probe.sh "$2"
    else
      docker logs -f --tail 5 "$(c probe)"
    fi
    ;;
  watch) docker exec "${TTY[@]}" "$(c raven)" raven watch --posture path-suspect ;;
  routes) raven routes --prefix 1.1.1.0/24 --format wide ;;
  leak)
    vtysh as262504 -c "configure terminal" -c "no route-map TO-AS1031 deny 10"
    softclear
    echo "as262504: route-map TO-AS1031 deny 10 removed; routes from AS53072 now exported to AS1031"
    ;;
  clean)
    vtysh as262504 -c "configure terminal" -c "route-map TO-AS1031 deny 10" \
      -c "match large-community FROM-AS53072"
    softclear
    echo "as262504: route-map TO-AS1031 deny 10 restored; routes from AS53072 no longer exported to AS1031"
    ;;
  *) usage ;;
esac
