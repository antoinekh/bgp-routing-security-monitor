# Loc-RIB lab

A small Containerlab topology that checks BMP Loc-RIB monitoring (RFC 9069) live: RAVEN must store each router's Loc-RIB apart from the Adj-RIB-In views, list it in the default view, and withdraw it correctly.

## Topology

```text
  ext1 AS64510 ──┐
                 ├── rr1 AS65000 ──── rr2 AS65000
  ext2 AS64520 ──┘   router-id 10.0.12.1
                     BMP: loc-rib      BMP: adj-rib-in-pre
                          │                 │
                          └──── RAVEN ──────┘ ◄── StayRTR (vrps.json)
```

| Node | Role |
|------|------|
| `ext1` | Announces `203.0.113.0/24`, `198.51.100.0/24`, `192.0.2.0/24` and `10.99.0.0/24` |
| `ext2` | Announces `203.0.113.0/24` with a longer path (`64520 64510`) |
| `rr1` | Rejects `10.99.0.0/24` on import, exports its Loc-RIB to RAVEN (BMP from `172.31.90.21`) |
| `rr2` | iBGP to rr1 on `10.0.12.1`, exports the pre-policy Adj-RIB-In of that session to RAVEN (BMP from `172.31.90.22`) |
| `raven` | The RAVEN binary built from this repository |
| `rtr` | StayRTR with three ROAs: `203.0.113.0/24` valid, `198.51.100.0/24` invalid, `192.0.2.0/24` not found |

RAVEN keys a route by its router (the BMP session's source address), the peer's distinguisher and address, the path ID and the RIB. A Loc-RIB has the zero peer address (RFC 9069), so rr1's Loc-RIB is the peer `0.0.0.0` (type `loc-rib`) on router `172.31.90.21`, and rr2's view of rr1 is the peer `10.0.12.1` (type `global`) on router `172.31.90.22`. rr1's router-id `10.0.12.1` is also the address rr2 peers with; the two views stay apart.

## Run

```bash
./run.sh all       # build, deploy, check, destroy
./run.sh up        # build and deploy only
./run.sh test      # run the checks against a deployed lab
./run.sh reset     # restore the routers' initial config, without redeploying
./run.sh down      # destroy
```

Containerlab needs root: run it with `sudo` (or as a user Containerlab allows). `up` builds the binary with the Go toolchain on the host.

Every wait gives up after `TIMEOUT` seconds (default 60) with a FAIL, what it last saw and a hint, and prints progress every 5 seconds. Every `vtysh` call is checked: a non-zero exit, or an FRR error or warning in its output (`% ...`; `vtysh -c` exits 0 on a warning), fails the run loudly with the router's output. A config change is checked in the router's running-config. A run that fails, errors or is interrupted (Ctrl-C) puts back the config its checks changed. If a lab is left in another state anyway, `./run.sh reset` restores it: `./run.sh test` checks the initial config first and says so.

The management network is `172.31.90.0/24`. The RAVEN API is at `http://172.31.90.10:11020/api/v1`, its metrics at `http://172.31.90.10:9595/metrics`.

```bash
curl -s http://172.31.90.10:11020/api/v1/routes | jq -c '.[] | {prefix, router, peer, peer_type, rib, as_path, posture}'
curl -s 'http://172.31.90.10:11020/api/v1/routes?rib=loc-rib' | jq -c '.[] | {prefix, as_path, posture}'
curl -s http://172.31.90.10:11020/api/v1/peers | jq -c '.[] | {router, addr, peer_type, table_name, asn, route_count}'
docker exec clab-loc-rib-raven raven --address 127.0.0.1:11020 status
docker exec clab-loc-rib-raven raven --address 127.0.0.1:11020 routes
docker exec clab-loc-rib-raven raven --address 127.0.0.1:11020 audit --router 172.31.90.21 --rib loc-rib
```

Without `rib`, route queries (`/api/v1/routes`, `/api/v1/watch`, `raven routes`, `raven watch`) return the default view, `adj-rib-in-pre` and `loc-rib`, so rr1, which sends only its Loc-RIB, does not show an empty table. `pre-policy` and `post-policy` are accepted as names of `adj-rib-in-pre` and `adj-rib-in-post`.

## Checks

| Step | Expected |
|------|----------|
| Preflight | rr1 has its BMP target, rr2 its target and an active session to rr1 (else: `./run.sh reset`) |
| Initial state | rr1's Loc-RIB (`loc-rib 0.0.0.0`) has its 3 routes, and any other rr1 peer (FRR 10.7.1 sends their Peer Up) has none; rr2 has one peer, `global 10.0.12.1`. The Loc-RIB holds one route per prefix, without the prefix rr1 rejects. rr2's pre-policy routes are stored apart. The default view lists both; `raven status` names its RIBs |
| ext1 withdraws two prefixes | The Loc-RIB drops `192.0.2.0/24`, and `203.0.113.0/24` moves to the ext2 path |
| rr2 shuts its session to rr1 | rr2's pre-policy routes are withdrawn, rr1's Loc-RIB routes stay |
| rr1 removes its BMP target | rr1's Loc-RIB routes are withdrawn and its `raven_bmp_peer_state` goes to 0; rr2's pre-policy routes stay. The target is put back and checked in rr1's running-config; rr1 reconnects and both come back |

## FRR notes

### Why rr1 is pinned to a release tag

rr1 runs `quay.io/frrouting/frr:10.7.1`. The checks depend on how FRR's BMP code behaves for the Loc-RIB, which has changed between versions (below), so the lab pins one release that has been run against it. A release tag names a published, reproducible image, where a master build moves daily and a digest of one says nothing about what it contains. Move the tag only with a lab run that passes on the new release, and note what changed here.

### FRR 10.7.1 (rr1)

- **Peer Up for its BGP neighbors.** rr1's target monitors only `loc-rib`, yet it sends a Peer Up for each of its three BGP neighbors as well as for its Loc-RIB instance. RAVEN lists them (type `global`, on router `172.31.90.21`) with 0 routes, since no Route Monitoring comes for them. The Initial state check expects that: the Loc-RIB has its routes, the other peers none.
- **BMP target syntax** (checked against FRR 10.7.1's `bgpd/bgp_bmp.c`): under `router bgp`, `bmp targets NAME` enters the target; inside it `bmp monitor ipv4 unicast loc-rib` and `bmp connect HOST port PORT min-retry MS max-retry MS` (100 to 86400000 ms). There is no `route-monitoring` keyword. `show running-config` prints the target as ` bmp targets raven`, `  bmp monitor ...`, `  bmp connect ...`, ` exit`, which is what `run.sh` checks for.
- **Reconnect.** `bmp connect` starts connecting as soon as it is configured, after `min-retry` (1 s here), then backs off by half each failure up to `max-retry` (5 s); removing the target (`no bmp targets raven`) closes the session at once. So with the target re-added rr1 reconnects within seconds, and the lab's config already sets these timers; none are missing. In the first run against 10.7.1, rr1 was left with no BMP target at all (`show bmp` empty, no `bmp` section in its running-config): the step that re-adds it never ran. The likely cause, from the old `run.sh` (not reproduced live): the check just before it, on `raven_bmp_peer_state`, expected a single series and could never match once the neighbor Peer Ups added theirs, and its `curl` calls had no time limit, so the run sat in that wait until it was interrupted. Nothing put the target back, so every later run failed at Initial state. Now every query is bounded, every wait times out, an interrupted run puts the target back, and `run.sh` verifies it in the running-config before waiting for the reconnect.
- **Withdrawals and best-path changes.** 10.7.1 sends Loc-RIB withdrawals and Loc-RIB updates on a best-path change: when ext1 withdrew `192.0.2.0/24` and `203.0.113.0/24`, RAVEN's Loc-RIB reflected it within 1 s, `192.0.2.0/24` withdrawn and `203.0.113.0/24` moved to the ext2 path (`64520 64510`). The lab passed 20/20 checks on 10.7.1. Not exercised: a withdrawal when a BGP session on the Loc-RIB router itself (rr1) goes down; the lab withdraws prefixes on ext1 rather than shutting a session on rr1. With the earlier master build, FRR sent no Loc-RIB withdrawal when a BGP session went down.

### Other routers

- rr2, ext1 and ext2 run FRR 10.2.5. FRR 10.2.5 as a Loc-RIB exporter sends no Loc-RIB Peer Up, puts its own AS first in the Loc-RIB AS_PATH, and sends no Loc-RIB message after a best path change. RAVEN registers a Loc-RIB from its first Route Monitoring message with routes or withdrawals, logs it at INFO (`BMP Loc-RIB registered`, `peer_up=false`), and removes a leading copy of the router's own AS before ASPA verification.
- rr2 needs `soft-reconfiguration inbound`: without it, FRR sends only End-of-RIB markers to a new BMP session in pre-policy mode.

### RTR and ASPA

StayRTR speaks RTR version 1. RAVEN asks for version 2, falls back to version 1 on the cache's Error Report, and re-probes version 2 hourly; the lab does not pin `rtr-version`. Version 1 carries no ASPA, and the lab sets `validation.aspa: false`, so every route's ASPA is Unknown (`ASPA disabled`; with `aspa: true` it would be `no ASPA data (no RTR v2 session)`), and postures are `unverified`, `origin-only` or `origin-invalid`, never `path-only` or `secured`.
