# Deployment Hardening

RAVEN opens up to four listeners: BMP for your routers, the HTTP API for the
CLI, the Prometheus metrics endpoint and, when you enable it, pprof. None of
them authenticates its clients, so who can reach each port is your access
control. This page explains what each listener exposes and how to restrict
it.

Start by checking what RAVEN actually bound. At startup it logs one
`listeners bound` line with the resolved address of each listener. With the
defaults and no `allowed-routers`, you see:

```json
{"time":"2026-10-18T22:19:48.267905655-04:00","level":"WARN","msg":"BMP listener accepts connections from any source on a non-loopback address; set bmp.allowed-routers to the routers' addresses","subsystem":"bmp","addr":"[::]:11019"}
{"time":"2026-10-18T22:19:48.268150928-04:00","level":"INFO","msg":"listeners bound","bmp":"[::]:11019","api":"127.0.0.1:11020","metrics":"[::]:9595"}
```

An address of `[::]` or `0.0.0.0` means every interface. Here BMP and
metrics are open to anything that can route to the host, and the API is
loopback only.

## Restrict BMP sources

Anything that can open a TCP connection to the BMP port can feed routes into
your route table, change every posture and metric RAVEN reports, and make it
parse attacker-chosen input. An internet scanner found an exposed BMP port
on a production RAVEN deployment within a day. Restrict BMP in two places.

**1. Set `bmp.allowed-routers`** to your routers' BMP source addresses:

```yaml
bmp:
  listen: ":11019"
  allowed-routers:
    - 192.0.2.10              # edge1
    - 192.0.2.11              # edge2
    - 2001:db8:100::/64       # core routers' loopbacks
```

RAVEN closes a connection from any other source at accept, before it reads
anything or starts a TLS handshake, logs `BMP connection rejected: source
not in bmp.allowed-routers` at WARN, and counts it in
`raven_bmp_rejected_connections_total{reason="not_allowed"}`. Alert on that
counter: see the `RAVENBMPRejectedConnection` rule in
[Observability & Metrics](../user-guide/observability.md#useful-promql-queries).

Use the address the router sources BMP from, which is often its loopback
rather than the interface facing RAVEN. If the router's sessions do not
appear after you set the list, look for the rejection WARN: it names the
address the router connected from.

With `allowed-routers` empty, RAVEN accepts any source and logs a WARN at
startup when the BMP listener is not on loopback. Treat that WARN as a
finding.

**2. Filter the port in the host firewall** as well. The allowlist protects
RAVEN; the firewall keeps the port closed to everyone else, keeps
connection attempts out of RAVEN's logs, and still holds if someone empties
the list in a config change. With nftables, for example:

```text
table inet raven {
  chain input {
    type filter hook input priority 0; policy accept;
    tcp dport 11019 ip saddr { 192.0.2.10, 192.0.2.11 } accept
    tcp dport 11019 ip6 saddr 2001:db8:100::/64 accept
    tcp dport 11019 drop
  }
}
```

If your routers support it, [BMP over TLS](../user-guide/configuration.md#bmp-listener-tls)
with a client CA adds router authentication on top.

## Keep the API on loopback

The HTTP API serves the CLI: the full route table, every peer, and the
what-if, audit and Flowspec endpoints, including
`POST /api/v1/flowspec/rules/<key>/toggle-dryrun`, which switches a Flowspec
rule from dry-run to live injection. It has no authentication. By
default it binds to `127.0.0.1:11020`, so only users with a shell on the
monitoring host can use it.

Keep that default and run the CLI on the monitoring host. If you need the
CLI elsewhere, prefer an SSH tunnel to opening the port. Open the tunnel in
the background, then run the CLI against your local end of it:

```bash
ssh -f -N -L 11020:127.0.0.1:11020 raven-host.example.net
```

```bash
raven routes --posture origin-invalid
```

If you do set `api.listen` to a routable address, bind it to a management
interface and firewall it to the hosts that run the CLI, as for BMP above.
See [`api.listen`](../user-guide/configuration.md#api-section).

## Decide who may scrape metrics

The metrics endpoint (`outputs.prometheus.listen`, default `:9595`) binds to
every interface. Metrics carry your routers' names and addresses, every BGP
peer's address, your RPKI caches' addresses, and route counts by posture,
which tells a reader how many of your routes fail validation. That is
reconnaissance value, so decide who needs it:

- If Prometheus runs on the same host, bind metrics to loopback:
  `listen: "127.0.0.1:9595"`.
- Otherwise bind it to the management interface and firewall it to your
  Prometheus servers.

## pprof stays on loopback

The pprof endpoint (`debug.pprof.listen`) is off by default. When you enable
it for a memory investigation, bind it to loopback, for example
`localhost:6060`, and reach it through an SSH tunnel. Profiles reveal process
memory contents, and the endpoint is unauthenticated. RAVEN does not stop
you binding it elsewhere, but it logs a WARN (`pprof endpoint is exposed
beyond localhost`) when the bound address is not loopback. Turn pprof off
again when you are done. See
[Memory Profiling](../user-guide/observability.md#memory-profiling-pprof).

## Checklist

| Listener | Setting | Default | Recommended |
|---|---|---|---|
| BMP | `bmp.listen`, `bmp.allowed-routers` | `:11019`, any source | Your routers only, by allowlist and host firewall |
| API | `api.listen` | `127.0.0.1:11020` | Loopback; SSH tunnel for remote CLI use |
| Metrics | `outputs.prometheus.listen` | `:9595` | Loopback or management interface, firewalled to Prometheus |
| pprof | `debug.pprof.listen` | off | Off; loopback only while profiling |
