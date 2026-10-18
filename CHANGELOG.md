# Changelog

All notable changes to RAVEN are recorded here.

## Unreleased

### Changed
- **Breaking:** the HTTP API the CLI talks to now binds to `127.0.0.1:11020`
  by default instead of every interface (`:11020`). Anyone running the CLI
  (`raven status`, `raven routes`, `raven watch`, ...) against a daemon on
  another host must now set `api.listen` (for example `"0.0.0.0:11020"`)
  on that daemon, and should restrict access to it. The Prometheus metrics
  listener is unchanged.

### Added
- `bmp.allowed-routers`: IP addresses and prefixes BMP connections are
  accepted from. Other sources are closed at accept, before any byte is
  read, logged at WARN and counted in
  `raven_bmp_rejected_connections_total{reason}`. Empty or absent still
  accepts any source, with a startup WARN when the BMP listener is not on
  loopback. Invalid entries fail config validation.
- `api.listen` sets the API's bind address.
- One startup INFO line, `listeners bound`, lists every listener (BMP, API,
  metrics, pprof if enabled) with the address it actually bound.
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
- Opt-in pprof profiling endpoint (`debug.pprof.listen`, off by default)
  for diagnosing memory growth on long-running daemons. Served on its own
  listener and mux, never on `http.DefaultServeMux`; warns at startup if
  bound beyond loopback.

### Fixed
- RTR anomaly detector no longer evaluates or contaminates its baseline
  with full (non-incremental) RTR syncs, which previously produced a
  false-positive high-severity anomaly on every `raven rtr monitor`
  startup.
- A router reconnecting while its old BMP session was still open could
  empty the route table: when the stale session finally closed, its
  withdraw-all removed the routes the new session had just re-announced
  (seen in production as 643k → 8k routes). Routes now record the BMP
  session that announced them, and peer-down and session-end withdraw-alls
  remove only that session's routes. A new session from a router that
  already has one open supersedes it: the old socket is closed, a WARN
  "superseding stale BMP session" is logged, and the old session's
  in-flight updates are dropped. A peer-down still also removes the peer's
  routes restored from a snapshot; a session end leaves those to stale
  eviction. Large withdraw-alls are applied in chunks between ingest
  events instead of blocking ingest.
  **Note:** "same router" means same source IP address. Routers that reach
  RAVEN through one NAT address will supersede each other's BMP sessions;
  give each router its own address.
- Re-validation after an RTR update could undo BMP ingest: it ran on the
  RTR goroutine alongside ingest, changed routes in place while the API and
  metrics were reading them, and re-inserted routes it had read earlier.
  A route withdrawn in the meantime could come back, and a route a newer
  BMP session had re-announced could be handed back to the older session
  (and removed with it when that session ended). Re-validation and stale
  eviction now run in the ingest loop, the route table's only writer, a
  chunk at a time between ingest events; RTR updates that arrive during a
  pass are coalesced into one follow-up pass. Each route is re-validated on
  a copy and swapped in with `Table.Replace` only if the table still holds
  that same route, so readers never see a half-updated route.
  `Engine.RevalidateAll` has been removed.
- The RTR client only queried a cache after a Serial Notify, so a cache that
  does not notify was never polled, and a quiet cache looked the same as a
  stuck client. It now polls at the Refresh Interval from each End of Data
  (RFC 8210 defaults when the cache sends none), fails a query unanswered
  within the Retry Interval, and logs an ERROR and sets
  `raven_rtr_data_expired{cache}` to 1 when no sync completes within the
  Expire Interval; the data is kept. `raven_rtr_last_sync_seconds` still
  records every completed sync; the new
  `raven_rtr_last_serial_change_seconds` records syncs that brought a new
  serial, and `rtr monitor` sync events carry `serial_changed`. A poll that
  finds nothing new no longer triggers a revalidation pass in `raven serve`.
  RTR connections (plain TCP and TLS) now use TCP keepalive (60s idle, 4
  probes 15s apart), so a dead cache or path is detected in about two
  minutes even between polls.
- RTR version negotiation treated every cache Error Report as a version
  problem and logged "falling back to RTR protocol version 1", but never
  actually stayed at the lower version, so a version-1-only cache could not
  be used at all. RAVEN now downgrades only on Error Report code 4
  (Unsupported Protocol Version) and keeps the negotiated version across
  reconnects. A downgraded client re-probes the configured version on a
  separate short connection every `rtr.version-reprobe-interval` (default
  1h), logging INFO; if the cache now accepts it the session reconnects at
  that version and ASPA sync resumes, otherwise a WARN says it stays
  downgraded for another interval and the running session is untouched.
  Code 2 (No Data Available, e.g. Routinator's "Running initial
  validation" at startup) is retried later at the same version, and
  `rtr monitor` reports it as a low-severity `cache_not_ready` event rather
  than a high-severity anomaly. The negotiated version is logged on every
  session and exported as `raven_rtr_protocol_version{cache}`; on a version
  0 or 1 session the ASPA store is cleared and a WARN says ASPA validation
  is unavailable.
  
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