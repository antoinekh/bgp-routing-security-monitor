# Changelog

All notable changes to RAVEN are recorded here.

## Unreleased

### Breaking changes
- ROV takes the origin AS as RFC 6811 §2 defines it. A route whose AS_PATH
  ends in an AS_SET has origin NONE: `Invalid` if a VRP covers the prefix,
  `NotFound` otherwise. Earlier releases used the set's last member, so
  some aggregates change from `Valid` to `Invalid`. Confederation segments
  never supply the origin.
- `raven validate` exits with an error when given `--origin-asn` or
  `--rtr`, which it used to accept and ignore. Remove them from scripts.
- The HTTP API now binds to `127.0.0.1:11020` by default instead of port
  11020 on every interface, and is configurable with the new `api.listen`
  key. If you run the CLI from another host with `--address`, set
  `api.listen` on the daemon to a reachable address and firewall it.
- `raven status` and the API's `route_table.total_routes` and `by_posture`
  now count Adj-RIB-In pre-policy routes only. Earlier releases added every
  RIB the routers sent, so routers sending post-policy or
  Adj-RIB-Out data inflated the totals. Dashboards built on those numbers
  will show lower, correct values.
- `raven_bmp_peer_state` gained the `router_addr` and `peer_distinguisher`
  labels. The same peer address on two routers, or in two VRFs of one
  router, is now two series.
- ASPA verification follows draft-ietf-sidrops-aspa-verification-24. The
  "first-hop" check of the neighbor-to-you edge, which required the
  neighbor's ASPA record to list your AS, was removed because the draft does
  not evaluate that edge. A route whose AS_PATH holds only the neighbor's AS
  now verifies as `Valid`, and sessions that showed `path-suspect` on every
  route because of that check no longer do.
- Snapshots are written in `format_version` 2. A snapshot from an earlier
  release is not restored; RAVEN starts with an empty route table and
  rebuilds it from the routers' BMP table dumps.

### Added
- RFC 7606 error handling for malformed BGP UPDATEs, mirroring the
  monitored router: attribute discard, treat-as-withdraw and session reset.
  Withdrawals apply even from malformed UPDATEs. Peers that send a
  session-reset error show a `MALFORMED` column in `raven peers` and
  `malformed_input`, `malformed_reason` and `malformed_since` in
  `/api/v1/peers`. New metric
  `raven_bmp_malformed_updates_total{action,reason}`; a WARN log line at
  most once a minute per peer and reason.
- `raven routes --rib` and the `rib` parameter on `/api/v1/routes` and
  `/api/v1/watch`: list one RIB (default `adj-rib-in-pre`), with every
  other filter applied within it.
- `--router` on `raven status` and `raven peers`. On `raven status` it
  limits the peer list; the totals stay daemon-wide.
- Route JSON `timestamp`: when the monitored router received the route,
  from the BMP per-peer header, in RFC 3339 UTC; RAVEN's receive time when
  the router sends 0.
- `rtr.expire-interval` now overrides every cache's Expire Interval,
  clamped to 600–172800 seconds, and RAVEN logs the interval in effect at
  startup. Earlier releases parsed the key and never used it.
- ASPA: routes whose AS_PATH has confederation segments are `Unverifiable`
  with an `aspa_reason` (draft-ietf-sidrops-aspa-verification-24 §6.2).
- `validation.aspa-peers`: map a BMP peer, by address or ASN, to its
  `neighbor-role` (`provider`, `customer`, `peer`, `rs`, `rs-client`).
  `provider` selects downstream ASPA verification, every other role
  upstream. Address entries take precedence over ASN entries; unmapped
  peers use `validation.aspa-default-procedure`, which is now honored
  (`auto` falls back to upstream until BGP Role parsing exists). Mapped
  peers other than `rs` also get the draft's neighbor-AS check.
- Route JSON gains `router`, `router_name`, `peer_distinguisher`,
  `path_id`, `aspa_procedure`, `aspa_procedure_source`, `aspa_reason` and
  `aspa_failing_hop`.
- `raven routes --format wide`, adding the `ASPA PROCEDURE`,
  `PROCEDURE SOURCE` and `FAILING HOP` columns. `raven routes` gains a
  `ROUTER` column, and `raven routes` and `raven watch` gain `--router`
  (router address or BMP sysName).
- `raven status` and `raven peers` gain a `ROUTER` column and, when any
  peer has Adj-RIB-Out routes, an `OUT` column.
- Routes are keyed by router, peer distinguisher, peer address, prefix,
  ADD-PATH path ID and RIB type. Two routers with the same peer address,
  VRF peers with the same address, and ADD-PATH paths no longer overwrite
  each other. ADD-PATH is negotiated per address family and direction from
  the Peer Up OPENs.
- `bmp.allowed-routers`: accept BMP only from listed addresses and
  prefixes. Other sources are closed at accept, logged at WARN and counted.
  With the list empty, RAVEN warns at startup when BMP listens on a
  non-loopback address.
- One `listeners bound` log line at startup with every listener's resolved
  address. A BMP bind failure now exits non-zero.
- BMP decoding: Adj-RIB-Out (RFC 8671), IPv4 unicast in
  `MP_REACH_NLRI`/`MP_UNREACH_NLRI` including RFC 8950 IPv6 next hops,
  per-family ADD-PATH, RFC 9072 extended optional parameters, and
  `AS4_PATH` merging for two-octet AS_PATHs. `make fuzz` runs the
  `FuzzBMPMessage`, `FuzzPeerUpOpen` and `FuzzDecodeUpdate` targets.
- Incremental revalidation: an RTR sync revalidates only the routes its
  VRP and ASPA changes can affect, instead of the whole table.
- New Prometheus metrics: `raven_aspa_validations_total{procedure,source,state}`,
  `raven_revalidation_duration_seconds{mode}`,
  `raven_revalidation_routes_total{mode,result}`,
  `raven_bmp_rejected_connections_total{reason}`,
  `raven_adj_rib_out_routes_total{posture,afi}` and
  `raven_bmp_unsupported_nlri_total{afi,safi}`. Counters and histograms
  with fixed label sets are exported at 0 from startup.
- On-demand global BGP visibility correlation via the RIPEstat Data API.
  RAVEN's ROV/ASPA validation is local-vantage-point only and cannot
  distinguish a globally propagated hijack from a purely local leak; this
  compares the local BMP-observed origin for a prefix against the origin
  ASNs that RIS route collectors see for it. Verdicts are `match`,
  `divergent`, `local_only` or `inconclusive`.
- `raven check global --prefix <cidr> [--origin-asn N] [--format table|json]`
  — one-shot correlation showing the local BMP view beside the global view
  with a consensus verdict. Works without a running daemon when
  `--origin-asn` is supplied.
- New `external.ripestat` config section (`enabled`, `base-url`, `timeout`,
  `cache-ttl`, `rate-limit-per-min`), defaulting to disabled. Existing
  `raven.yaml` files are unaffected without an explicit opt-in.
- New Event Engine action type `global-correlate`, configurable per rule
  with an optional `cache_ttl`. It runs before the rule's other actions and
  annotates the event, so webhook payloads gain a `global_visibility` field
  and the `log` action gains `global_*` keys. Rules that do not use it are
  unaffected. Correlation runs in the Event Engine's own goroutines behind a
  per-prefix cache, a token-bucket rate limiter and a concurrency bound —
  never on the BMP ingest or validation path, and with no per-route external
  HTTP calls.
- New Prometheus metrics: `raven_global_check_total{source,result}`,
  `raven_global_check_latency_seconds`,
  `raven_global_check_rate_limited_total{source}` and
  `raven_global_check_cache_hits_total{source}`. The last two count the
  lookups that made no network round-trip — suppressed by the local rate
  limiter, or served from the in-process cache — and are deliberately kept
  off the latency histogram, which covers live lookups only. A policy
  decision and a warm cache must both stay distinguishable from a provider
  RAVEN could not reach.

  The result is a standalone annotation: it does not feed into
  `SecurityPosture` and the ROV × ASPA posture matrix is unchanged. The
  whole path is fail-open — an unreachable, slow or malformed RIPEstat
  degrades to `inconclusive` and never crashes RAVEN or blocks an action.
- Grafana: Global BGP Visibility Correlation dashboard row — consensus
  results timeseries, current totals stat panel, RIPEstat query performance,
  and latency p50/p95 panels (panels 17–20).
- RTR anomaly detection: adaptive median/MAD-based detector for RTR sync
  telemetry (interval, duration, VRP/ASPA churn) with per-cache rolling
  baselines, hard-trip and correlated-trip classification.
- Restart-safe baseline persistence via `--anomaly-snapshot` on
  `raven rtr monitor` — anomaly detector windows survive process restarts.
- `raven rtr seed-baseline` command to seed a detector baseline from
  historical NDJSON telemetry, avoiding the ~25-hour warm-up window on
  every fresh deployment.
- New Prometheus metrics: `raven_rtr_anomaly_total`,
  `raven_rtr_anomaly_last_timestamp`.
- `lab/04-rtr-anomaly.sh` Containerlab demo scenario for live RTR
  anomaly detection (bulk SLURM ROA injection, serial-based confirmation).

### Fixed
- `RAVEN_*` environment variable overrides had no effect. They now work
  for every non-list config key, with dots and dashes mapped to
  underscores (`RAVEN_BMP_LISTEN`, `RAVEN_RTR_EXPIRE_INTERVAL`).
- A Route Monitoring message with a BGP Length under 19 crashed the
  daemon.
- `--prefix` and `--origin-asn` on `raven routes` returned routes from
  every RIB; every query now returns one RIB.
- `raven routes` applied only the first of `--prefix`, `--origin-asn`,
  `--peer` and `--posture`; every filter given now applies. `raven watch`
  sent only `--posture` to the daemon; it now sends every filter.
- Per-peer route counts counted every announced prefix in every UPDATE and
  never decreased on withdrawal. They now reflect the route table.
- VRP changes rebuilt the whole VRP index under a write lock for every
  withdrawn VRP, stalling ROV lookups and BMP ingest (81 minutes for one
  8,882-VRP withdrawal in production). VRP changes now publish once at
  End of Data through an off-lock rebuild and atomic swap, and routes keep
  validating against the previous VRP set during a full sync.
- A post-policy withdrawal no longer removes the pre-policy route, and a
  peer-down on one router no longer removes other routers' routes.
- A Withdrawn Routes Length longer than the UPDATE crashed the daemon; BMP
  messages are now capped at 1 MiB.
- RTR Error Report code 2 ("No Data Available", sent by Routinator during
  initial validation) is treated as cache-not-ready, not as an anomaly.
- A `raven.yaml` that exists but does not parse is now fatal. RAVEN prints
  the error (naming the offending file) to stderr and exits 1. Previously a
  YAML syntax error printed one line and then started the daemon anyway on
  silently-defaulted config — `rtr_caches:0`, no BMP peers, no event rules,
  exit 0 — so a single mis-indented key left an operator with a daemon that
  looked healthy and validated nothing. A missing config file stays
  non-fatal: RAVEN still runs on defaults when no `raven.yaml` exists.
- Global-visibility lookups suppressed by the local rate limiter are no
  longer reported as queries. The result now carries `queried: false` and
  no `latency_ns`, instead of `queried: true` with a sub-microsecond
  latency for a call that never left the process. They are counted on the
  new `raven_global_check_rate_limited_total{source}` rather than folded
  into `raven_global_check_total{result="inconclusive"}`, and contribute no
  observation to `raven_global_check_latency_seconds`, which now describes
  only real network attempts. In Prometheus and Grafana, "the rate limiter
  fired" and "RIPEstat was unreachable" are now separate signals.
- CLI errors are now printed to stderr. The root command sets
  `SilenceErrors`, so cobra did not print returned errors and `main`
  discarded them — every CLI failure exited 1 with no output at all,
  including config validation errors and commands' actionable hints.
- RTR anomaly detector no longer evaluates or contaminates its baseline
  with full (non-incremental) RTR syncs, which previously produced a
  false-positive high-severity anomaly on every `raven rtr monitor`
  startup.
- Upstream ASPA verification (`internal/validation/aspa`) now checks the
  first hop of the AS_PATH — whether the immediate peer AS lists the
  monitoring router's own AS as an authorised provider. This check
  previously stopped one hop short, so a real route-propagation
  misconfiguration over a peering session without a matching ASPA
  provider entry resolved as `ASPA:Unknown` instead of `ASPA:Invalid`.
  Single-AS-path routes, previously short-circuited to `Unknown` with no
  check at all, are now actually evaluated.
- Adds `LocalASN` to `Route`, learned per BMP session from the Peer Up
  message's Sent OPEN (RFC 6793 four-octet AS capability preferred when
  present) via new `parseOpenLocalASN()` in `internal/bmp/parser.go`.
  No config changes needed.

### Changed
- Any direct BGP session where the peer's ASPA record does not list the
  local AS as a provider now shows `path-suspect` for every prefix
  received over that session — not just customer-originated
  misannouncements, but connected-link and infrastructure prefixes too.
  This is correct per draft-ietf-sidrops-aspa-verification, not a
  regression; see
  [Security Postures](user-guide/security-postures.md#path-suspect).

### Documentation
- Concepts: ASPA Path Verification rewritten for draft-24 (origin-to-
  neighbor verification, upstream and downstream procedures, procedure
  selection, the neighbor-AS check and route servers).
- Attack Scenarios: Scenario 13 (first-hop route-leak detection) replaced by
  an "under revision" note.
- Configuration: `bmp.allowed-routers`, `api.listen`,
  `validation.aspa-peers` and `validation.aspa-default-procedure`.
- CLI Reference: `raven status`, `raven peers`, `raven routes` and
  `raven watch` updated, with examples generated from the CLI's formatters.
- Observability: new metrics, the `raven_bmp_peer_state` label change, and
  the RTR cache metrics corrected to the ones RAVEN exports.
- New pages: Deployment Hardening, Architecture: Data Model, Architecture:
  Validation Engine.
- Quick Start: `raven status` sample output re-captured from the current
  formatter. CLI Reference: `raven validate` corrected to the flags and
  columns it has.
- Troubleshooting and Scaling: removed `raven status --format json`,
  `raven_rtr_cache_stale` and the `staleness-threshold` key, none of which
  exist; RTR checks now use `raven_rtr_data_expired`,
  `raven_rtr_last_sync_seconds`, `raven_rtr_protocol_version` and
  `raven_rtr_aspa_count`.
- Configuration: `rtr.expire-interval` and environment variable overrides
  documented as they work now.
- Troubleshooting: new Malformed BGP Input section. Validation Engine: the
  RFC 6811 origin rules and the routes RAVEN does not ASPA-verify. CLI
  Reference: `--rib`, `--router` on `status` and `peers`, the `MALFORMED`
  column, the route `timestamp`, and the `raven validate` errors.
- Quick Start: Step 2 shows real startup log lines. Demo Lab overview:
  the setup output now matches what `demo-master.sh` prints.
- Attack Scenarios: note that sample output predates the `ROUTER` and ASPA
  procedure columns.

## v0.3.3 (2026-07-02)

### Added
- RTR session telemetry: structured per-sync event capture (VRP/ASPA
  announced/withdrawn deltas, sync duration, interval between serial
  advances, sync type full vs incremental) wired into the RTR client
  at four points: session connect, EndOfData, PDUCacheReset, and
  PDUErrorReport. Events written as NDJSON and mirrored on a buffered
  channel for downstream consumers.
- `raven rtr monitor` command: standalone RTR cache observer for
  baseline data collection and diagnostics. Config-file-free (flags
  only: `--cache`, `--log-file`, `--transport`, `--prometheus`).
  Graceful shutdown with bounded 70s grace period. Optional Prometheus
  endpoint. Useful for characterising normal RTR behaviour before
  deploying full RAVEN.
- `tls-min-version` config option for RTR and BMP TLS transports.
  Accepts `1.2` or `1.3`; defaults to TLS 1.2 minimum. Addresses
  operator transport security requirements (Orange/AS3215).

### Fixed
- RTR client: 65s read deadline with benign-timeout handling prevents
  shutdown from blocking indefinitely on idle caches while avoiding
  spurious reconnects on healthy sessions.
- RTR client: proto version reset to configured starting version on
  each reconnect, preventing permanent version downgrade caused by
  transient errors during cache startup.
- Telemetry event channel drained in standalone `rtr monitor` mode
  to prevent buffer fill and drop warnings during sustained reconnect
  loops.

### Changed
- Grafana: BGP Peers panel filtered to IPv4-only peers, height
  increased to accommodate IPv6 peer additions.

## v0.3.2 (2026-06-16)

### Fixed
- Demo lab: all `docker exec` calls in `demo-master.sh` now use `sudo` (silent
  injection failures occurred when run without root)
- Demo lab: `setup()` now injects `LEAK-PREFIX` prefix-list into running FRR
  containers via `vtysh` post-deploy; Containerlab mounts `frr.conf` but FRR
  does not reload on redeploy, causing the leak scenario to fail on cold start
- Demo lab: Routinator 0.15.1 changed CLI syntax; `--config` flag must now be
  passed as a global flag before the subcommand
  (`routinator -c ~/.routinator.conf server`) not after it
- Grafana: BGP Peers panel filtered to IPv4-only peers and panel height
  increased (IPv6 peer additions doubled tile count, causing overflow)

## v0.3.1 (2026-06-08)

### Added
- IPv6 route monitoring via BMP (`MP_REACH_NLRI` / `MP_UNREACH_NLRI` parsing)
- IPv6 ROV validation
- IPv6 origin hijack scenario in demo lab (`./demo-master.sh hijack6`)
- TLS support for BMP listener and RTR client; skip TCP buffer tuning
  (`SetReadBuffer`/`SetWriteBuffer`) for TLS connections (WSL2 compatibility)

### Fixed
- Demo lab: `lacnic` scenario 4 route leak used inline `LEAK-INJECT` route-map
  with wrong prepend ASN (AS64496 → ROV:Invalid); replaced with permanent
  `ROUTE-LEAK` route-map (prepend AS1199 → ROV:Valid, ASPA:Invalid,
  posture:path-suspect as intended)
- Demo lab: `leak` and `hijack6` vtysh commands converted to heredoc syntax
  (`docker exec ... bash -c "vtysh << 'VTYSH' ... VTYSH"`) to fix silent
  failures caused by leading spaces in `-c` arguments
- Demo lab: leak scenario prefix corrected to `193.0.0.0/21` (AS3333 /
  RIPE NCC); SLURM ASPA assertion added for AS3333 with provider AS1103
  (excluding AS65000 to trigger path-suspect)

### Changed
- Demo lab internet router ASN changed from AS2121 to AS64496 to avoid
  spurious `path-suspect` at baseline caused by real-world RPKI/ASPA
  records for AS2121

## v0.3.0 (2026-05-26)

### Added
- Event Engine: configurable triggers on posture changes
  (ROV state change, new route with specific posture,
  RTR cache failure) with webhook HTTP POST and file
  log actions
- Flowspec lifecycle management: detect origin-invalid
  route → generate Flowspec rule → inject via GoBGP →
  monitor → expire after configurable TTL. Dry-run mode
  and approval webhook supported.
- `raven audit` — full security posture report for a
  router: per-peer posture breakdown, ROV/ASPA coverage,
  recommendations. Outputs table, JSON, or markdown.
- `raven check stealthy` — detect stealthy BGP hijacks
  by comparing BMP control-plane view against data-plane
  forwarding via probes
- Warm-start persistence: snapshot route table and RPKI
  caches to disk on shutdown, restore on startup
- OpenTelemetry OTLP metrics export alongside Prometheus
- RTR-over-TLS: configure `transport: tls` and optional
  CA cert under any RTR cache entry
- BMP listener TLS: optional TLS termination on the BMP
  listener with mutual TLS support
- Event Engine ASN triggers: `asn` and `protected_asn`
  trigger types (contributed by Orange/AS3215)

### Fixed
- RTR `rtr-version` config field now correctly wired
  through to the client (was previously ignored)
- TCP socket buffer tuning skipped for TLS connections
  (prevented TLS sessions from establishing on some
  platforms)

## v0.2.0 (2026-05-18)

### Added
- ASPA path verification per draft-ietf-sidrops-aspa-verification-24
- Combined security posture matrix: Secured / Origin-Only / Path-Suspect /
  Path-Only / Unverified / Origin-Invalid
- ASPA store populated via RTR v2 ASPA PDUs; re-validation on ASPA
  store updates via dirty-set propagation
- `raven aspa` — show ASPA records for an ASN
- `raven aspa recommend` — suggest ASPA objects based on observed paths
- `raven what-if` — simulate impact of reject-invalid or ASPA enforcement
- `raven watch` — stream live validation state changes
- Prometheus posture metrics reflect full ROV × ASPA matrix

## v0.1.0 (2026-04-15)

Initial public release — Phase 1 (Foundation) complete.

### BMP Ingest
- Embedded BMP receiver (RFC 7854) on configurable TCP port (default: 11019)
- Parses BGP UPDATE messages from BMP Route Monitoring PDUs
- Supports Adj-RIB-In Pre-Policy, Post-Policy, and Loc-RIB
- Per-session lifecycle management (Initiation, Peer Up/Down, Termination)

### RPKI / RTR Client
- RTR v1 (RFC 8210) and RTR v2 (draft-ietf-sidrops-8210bis) client
- VRP store for Route Origin Validation
- Multi-cache support with preference ordering and automatic failover
- Re-validation on RPKI cache updates via dirty-set propagation

### Validation Engine
- Route Origin Validation (ROV) per RFC 6811: Valid / Invalid / NotFound

### CLI
- `raven serve` — start daemon
- `raven status` — BMP peer and RTR cache health
- `raven peers` — list BMP peers
- `raven routes` — query route table with filters (prefix, origin-asn, peer, posture)
- `raven validate` — one-shot prefix validation

### Observability
- Prometheus metrics endpoint (default: 9595)
- Pre-built Grafana dashboards (Security Posture Overview, Per-Peer Deep Dive)

### Demo Lab
- Containerlab topology: internet AS64496 → upstream AS65000 → edge AS65001
- Scripted demo scenarios: origin hijack, route leak
