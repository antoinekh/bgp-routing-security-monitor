# DNS-OARC 47 demo: the 1.1.1.1 route leak, seen by RAVEN

A self-contained Containerlab lab that replays the route-leak half of the
27 June 2024 1.1.1.1 incident. One scenario, built for a 20-minute talk.

## What the demo shows

An operator's edge router, **vantage** (AS64500), reaches Cloudflare's
1.1.1.0/24 through its provider **transit** (AS64510). A customer behind
vantage, **probe**, queries the 1.1.1.1 anycast service once a second and
sees the YVR instance (NSID `yvr`, about 5 ms away).

```
  cf-yvr AS13335 ── transit AS64510 ── vantage AS64500 ── probe
     dns-yvr   (5 ms netem)               │  IX peer, local-pref 200
  cf-gru AS13335 ── as7738 ── as53072 ══ as262504 ── as1031
     dns-gru                  (150 ms netem)
```

AS262504 learns 1.1.1.0/24 from AS53072 and, normally, does not export it
to AS1031. **The leak is AS262504 removing that export filter**, which is
what happened. AS1031 passes the route on to vantage, which prefers it
(IX peer, local-pref 200 over transit's 100). The probe's answers move to
the GRU instance (NSID `gru`) and pick up the 150 ms of the long path.

RAVEN receives vantage's BMP feed (Adj-RIB-In pre-policy) and validates
every route against RPKI. The leaked route is ROV Valid (the origin is
still AS13335) but **ASPA Invalid**: AS53072's ASPA lists its providers as
AS16735, AS23106 and AS270735, and AS262504 is not one of them. `raven
watch` flags it as `path-suspect` and names the failing hop:
`ASPA:Invalid hop(53072→262504)`.

The RPKI objects in lab mode mirror the real records: the 1.1.1.0/24
ROA for AS13335, and AS53072's ASPA with provider set {AS16735, AS23106,
AS270735}. They are re-issued in a local Krill so the demo runs offline;
see RPKI_MODE below.

## Demo command order

```bash
./preflight.sh          # all checks PASS, probe answers from yvr
./demo.sh probe         # pane 1: the probe's queries, live (Ctrl+C to stop)
./demo.sh watch         # pane 2: raven watch for path-suspect routes
./demo.sh routes        # 1.1.1.0/24 via transit only, ASPA Unknown, origin-only
./demo.sh leak          # AS262504 drops its export filter
                        # pane 1 flips to nsid=gru at ~150 ms;
                        # pane 2 prints the path-suspect line with hop(53072→262504)
./demo.sh routes        # now also via as1031: ASPA Invalid, FAILING HOP 53072->262504
./demo.sh clean         # filter restored; probe back to yvr
./demo.sh status        # raven status: route table, RPKI, BMP peers
```

`raven watch` streams changes only, so start `./demo.sh watch` before
`./demo.sh leak`. `./demo.sh probe N` runs N fresh queries and exits instead
of following the probe's log. Grafana, with the RAVEN dashboard from
`lab/grafana-dashboard.json`, is at `http://localhost:3047` (user `admin`,
password `GRAFANA_ADMIN_PASSWORD` from `.env`; anonymous viewing is on).

## Scripts

Each is run by hand; none runs another.

| Script | What it does |
|---|---|
| `bootstrap.sh` | Builds `bin/raven` (static linux/amd64, with the host's Go or in a pinned golang image), prepares `runtime/`, and in lab mode sets up Krill and issues exactly the two RPKI objects and installs the Krill TAL. Idempotent. |
| `deploy.sh` | `containerlab deploy`, then netem, left on: 150 ms on as53072 eth2 (toward as262504) and 5 ms on cf-yvr eth1 (toward transit). Waits for BGP, BMP and, in lab mode, RPKI. |
| `destroy.sh` | `containerlab destroy --cleanup`. Keeps `runtime/` and `bin/`. |
| `preflight.sh` | Exits non-zero, saying which check failed, unless: all 7 BGP sessions are Established; vantage's BMP peers are up in `raven status`; the RTR session is up with VRPs > 0; AS53072 has an ASPA without AS262504; 1.1.1.0/24 from AS13335 is ROV Valid; the probe gets NSID `yvr`; both netem delays are in place. |
| `demo.sh` | `status`, `probe [N]`, `watch`, `routes`, `leak`, `clean`. |

## RPKI_MODE

Set in `.env` (copy `.env.example`; `.env` is gitignored).

**`lab`** (the laptop default). Routinator runs with `--no-rir-tals`: it
trusts no RIR, only the Krill testbed TA in this lab. Krill runs in testbed
mode (an embedded TA and a `testbed` CA holding all resources); an rsync
sidecar (`krill-rsync`) serves the rsync URIs in Krill's TAL and
certificates; Routinator fetches over RRDP from Krill's HTTPS, trusting the
lab CA that signed Krill's certificate (`--rrdp-root-cert`). bootstrap.sh
issues exactly:

- ROA `1.1.1.0/24 maxLength 24 => AS13335`
- ASPA `AS53072 => {AS16735, AS23106, AS270735}`

These mirror the real records. Nothing in lab mode needs the internet, so it
works behind TLS interception and with rsync blocked.

**`live`** (the server). Routinator validates the real RPKI with the five
RIR TALs bundled with Routinator 0.15.2 (AFRINIC, APNIC, ARIN, LACNIC,
RIPE; `routinator --tal list` shows them, all enabled by default, no flags
needed). It does not trust Krill, and no lab objects are issued. Krill and
its rsync sidecar stay deployed but nothing trusts them. The Routinator
repository cache is a persistent bind mount (`ROUTINATOR_CACHE_DIR`), so
only the first deploy pays for a cold sync; until it finishes, preflight's
RTR check fails.

## Moving from the laptop to the server

On the laptop, commit and push. The checkout is on the Windows filesystem
with `core.filemode=false`, so record the scripts as executable explicitly:
`git add --chmod=+x lab/dns-oarc/*.sh`. On the server (Ubuntu 24.04 with Docker and containerlab;
the user in the `docker` and `clab_admins` groups, or with sudo):

```bash
git clone <the repository you pushed to> raven                        # first time only
cd raven && git checkout <your branch>                                 # first time only
cd lab/dns-oarc
cp .env.example .env && sed -i 's/^RPKI_MODE=.*/RPKI_MODE=live/' .env  # first time only;
                                       # also set GRAFANA_ADMIN_PASSWORD in .env
git pull && ./bootstrap.sh && ./deploy.sh
./preflight.sh
```

`.env`, `bin/` and `runtime/` are gitignored and stay local to each machine.
On a native Linux filesystem Krill writes `runtime/krill/` as root. To start
Krill from scratch, destroy the lab and remove it through a container:
`docker run --rm --entrypoint sh -v "$PWD/runtime:/r" nlnetlabs/krill:v0.16.0 -c 'rm -rf /r/krill'`,
then run `./bootstrap.sh` again.
Go is optional on the server: without it, bootstrap.sh builds RAVEN in the
pinned golang image.

On the laptop (WSL2 with the checkout under `/mnt/c`), `.env` sets
`ROUTINATOR_CACHE_DIR` to a Linux-filesystem path: Routinator's rsync cannot
set file times on the 9p mount.

## Addressing

| What | Where |
|---|---|
| mgmt `dnsoarc-mgmt` | 172.31.47.0/24: routers .11–.18, dns-yvr .21, dns-gru .22, probe .23, raven .31, routinator .32, krill .33, krill-rsync .34, prometheus .35, grafana .36 |
| Router links | 10.47.N.0/30 (RFC 1918), N = 1, 2, 4–10 as commented in `dnsoarc.clab.yaml` |
| Probe | 198.51.100.0/24 (RFC 5737), announced by vantage; probe is .10 |
| Anycast | 1.1.1.1/32 on dns-yvr and dns-gru loopbacks; 1.1.1.0/24 announced by cf-yvr and cf-gru |

Only Grafana publishes a host port (3047). Routers drop the mgmt default
route at deploy, so a missing BGP route can never send probe traffic to the
real 1.1.1.1. The probe prefix reaches both DNS instances in both states:
via transit to cf-yvr, and via as1031 … as7738 to cf-gru, so replies return
whichever instance answers.

The CoreDNS image has no shell or `ip` tool, so each DNS node has a netshoot
sidecar (`dns-yvr-net`, `dns-gru-net`) in its network namespace that adds
1.1.1.1/32, the link address and the default route.

AS262504 tags routes from AS53072 with the large community
`262504:0:53072` (RFC 8092): a 4-byte ASN does not fit a standard `AA:NN`
community.

## Pinned images

| Image | Used for |
|---|---|
| `quay.io/frrouting/frr:10.7.1` | the eight routers (FRR 10.7.1, released 2026-08-31) |
| `coredns/coredns:1.12.1` | dns-yvr, dns-gru |
| `nicolaka/netshoot:v0.13` | probe (dig), dns-*-net sidecars |
| `debian:12.11-slim` | raven (binary bind-mounted from `bin/raven`) |
| `nlnetlabs/routinator:v0.15.2` | routinator; also krill-rsync (its rsync binary) |
| `nlnetlabs/krill:v0.16.0` | krill; bootstrap.sh's temporary Krill and certificate generation |
| `prom/prometheus:v3.10.0` | prometheus |
| `grafana/grafana:12.4.1` | grafana |
| `golang:1.25.0-bookworm` | bootstrap.sh builds RAVEN in it only when the host has no Go |

## FRR version

The routers run FRR 10.7.1 (GitHub release `frr-10.7.1`, published
2026-08-31). FRR 10.2.5, used by the older lab in `lab/`, puts the monitoring
router's own AS at the front of the AS_PATH in BMP pre-policy Route
Monitoring messages; 10.7.1 sends the path as received, so RAVEN sees the
leaked route as `1031 262504 53072 7738 13335`. `configs/frr/daemons` is
10.7.1's default file with `bgpd=yes` and `-M bmp` added.
