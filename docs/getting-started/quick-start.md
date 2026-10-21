# Quick Start

This guide gets you from zero to seeing your first annotated routes in minutes.

## What You Need

- RAVEN binary installed (see [Installation](install.md))
- At least one BMP-capable router
- An RPKI validator running RTR (Routinator recommended)

## Step 1 — Create a Config File

Create `raven.yaml` in your working directory:

```yaml
bmp:
  listen: ":11019"

rtr:
  caches:
    - address: "localhost:3323"
      preference: 1

validation:
  rov: true
  aspa: true

outputs:
  prometheus:
    listen: ":9595"
    path: "/metrics"

logging:
  level: info
  format: json
```

## Step 2 — Start RAVEN

```bash
raven serve --config raven.yaml
```

RAVEN logs one JSON object per line. With the config above and Routinator
still running its first validation, startup looks like this:

```json
{"time":"2026-10-18T23:53:32.681202942-04:00","level":"INFO","msg":"starting raven","version":"dev","commit":"unknown"}
{"time":"2026-10-18T23:53:32.698781115-04:00","level":"INFO","msg":"BMP listener started","subsystem":"bmp","addr":"[::]:11019","transport":"tcp","allowed_routers":0}
{"time":"2026-10-18T23:53:32.699037906-04:00","level":"WARN","msg":"BMP listener accepts connections from any source on a non-loopback address; set bmp.allowed-routers to the routers' addresses","subsystem":"bmp","addr":"[::]:11019"}
{"time":"2026-10-18T23:53:32.6997368-04:00","level":"INFO","msg":"listeners bound","bmp":"[::]:11019","api":"127.0.0.1:11020","metrics":"[::]:9595"}
{"time":"2026-10-18T23:53:32.700023699-04:00","level":"INFO","msg":"starting RTR clients","count":1}
{"time":"2026-10-18T23:53:32.700688488-04:00","level":"INFO","msg":"RTR expire interval: each cache's own (End of Data)","expire_interval":"cache"}
{"time":"2026-10-18T23:53:32.701255669-04:00","level":"INFO","msg":"RAVEN started","bmp_listen":":11019","rtr_caches":1,"rov_enabled":true}
{"time":"2026-10-18T23:53:32.700086153-04:00","level":"INFO","msg":"route ingest pipeline started"}
{"time":"2026-10-18T23:53:32.702104253-04:00","level":"INFO","msg":"waiting for RTR sync before annotating routes..."}
{"time":"2026-10-18T23:53:32.700281373-04:00","level":"INFO","msg":"Prometheus metrics endpoint started","addr":"[::]:9595","path":"/metrics"}
{"time":"2026-10-18T23:53:32.702509219-04:00","level":"INFO","msg":"API server started","subsystem":"api","addr":"127.0.0.1:11020"}
{"time":"2026-10-18T23:53:32.705207585-04:00","level":"INFO","msg":"RTR connected","subsystem":"rtr","cache":"localhost:3323","transport":"tcp","protocol_version":2}
{"time":"2026-10-18T23:53:32.706773811-04:00","level":"INFO","msg":"RTR cache not ready, reconnecting","subsystem":"rtr","cache":"localhost:3323","error":"cache has no data available yet (Running initial validation)","retry_in":5000000000,"protocol_version":2}
```

What to look for:

- **`listeners bound`** shows the address each listener bound. The API is
  on loopback by default.
- **The WARN about `bmp.allowed-routers`** is expected in a first test. Set
  `bmp.allowed-routers` before you run RAVEN anywhere a stranger can reach
  the BMP port; see [Deployment Hardening](../deployment/hardening.md).
- **`RTR cache not ready, reconnecting`** means Routinator is still running
  its first validation. That is not an error: RAVEN retries with a growing
  delay (`retry_in` is in nanoseconds) and holds route annotation until the
  cache has data.

Once Routinator has data, RAVEN logs `RTR session established`, then
`RTR sync complete` with the cache's `vrp_count` and `aspa_count`, then
`RTR ready — starting route annotation`. If `aspa_count` stays 0, see
[ASPA Validation Not Working](../troubleshooting.md#aspa-validation-not-working).

## Step 3 — Configure Your Router

Point your router's BMP configuration at RAVEN's BMP listener.

**FRR example:**

```text
router bgp 64496
 bmp targets raven
  bmp monitor ipv4 unicast pre-policy
  bmp monitor ipv6 unicast pre-policy
  bmp connect 192.0.2.10 port 11019 min-retry 1000 max-retry 5000
 exit
exit
```

To validate the routes the router selected rather than every route it
received, monitor its Loc-RIB instead of, or as well as, pre-policy
(`bmp monitor ipv4 unicast loc-rib`); see
[Loc-RIB Monitoring](../user-guide/loc-rib.md).

**SR Linux example:**

```text
network-instance default {
protocols {
bgp {
bmp {
station raven {
connection {
destination-address 192.0.2.10
destination-port 11019
}
local-address 0.0.0.0
}
}
}
}
}
```

## Step 4 — Check Peer Status

Once your router connects:

```bash
raven status
```

```text
RAVEN dev  uptime 4m12s

Route Table: 1160117 routes in the default view (adj-rib-in-pre + loc-rib)
  secured              10214
  path-only            742
  origin-only          601877
  unverified           540112
  path-suspect         300
  origin-invalid       6872
By RIB:
  adj-rib-in-pre       1160117

RPKI: 786344 VRPs (serial 4821)

BMP Peers: 2
  ROUTER  PEER          TYPE    ASN    STATE  ROUTES
  edge1   198.51.100.1  global  64496  up     948213
  edge1   2001:db8::1   global  64496  up     211904
```

Each row under **BMP Peers** is one BGP session on your router, which BMP
reports as a peer. `ROUTER` is the router's BMP sysName and `ROUTES` is what
that peer sent before your import policy. If `ROUTES` is still climbing, the
router is sending its initial table dump; wait for it to settle before you
query routes. A `RPKI:` line with 0 VRPs means RAVEN has not completed a
sync with your validator yet. See
[`raven status`](../user-guide/cli-reference.md#raven-status) for every
column.

## Step 5 — Query Your Routes

```bash
# Show all routes with their security posture
raven routes

# Show only routes failing ROV
raven routes --posture origin-invalid

# Show routes with ASPA path violations
raven routes --posture path-suspect

# Show routes for a specific prefix
raven routes --prefix 1.0.0.0/24
```

## Step 6 — Watch for Problems in Real Time

```bash
raven watch --posture origin-invalid
```

This streams any new origin-invalid routes to your terminal as they arrive.
Leave it running — it will catch hijacks and ROV state changes as they happen.

## Step 7 — Run a What-If Simulation

```bash
raven what-if --reject-invalid
```

This shows you how many routes would be dropped if you deployed reject-invalid
policy today — without changing anything on your routers.

## Next Steps

- [Configuration](../user-guide/configuration.md) — full config file reference
- [CLI Reference](../user-guide/cli-reference.md) — every command and flag
- [Security Postures](../user-guide/security-postures.md) — what each posture means and what to do
- [Demo Lab](../lab/overview.md) — run attack scenarios on your laptop
