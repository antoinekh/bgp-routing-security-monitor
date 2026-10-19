package bmp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nokia/bgp-routing-security-monitor/internal/config"
	"github.com/nokia/bgp-routing-security-monitor/internal/metrics"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// Listener accepts BMP connections from routers and processes messages.
type Listener struct {
	addr     string
	tlsCfg   *tls.Config // nil = plain TCP
	log      *slog.Logger
	ingestCh chan<- types.IngestEvent
	peerMu   sync.RWMutex
	peers    map[PeerKey]*Peer
	routerMu sync.RWMutex
	routers  map[netip.Addr]routerInfo
	listener net.Listener

	// allowed lists the source prefixes BMP connections are accepted from
	// (IPv4 sources in plain form); empty accepts any.
	allowed []netip.Prefix

	lastSession atomic.Uint64 // last session ID handed out; IDs start at 1
	sessMu      sync.Mutex
	sessions    map[netip.Addr]*bmpSession // the current session per router address

	// testBeforeSend, nil in production, runs in emitFrom with the
	// session's send lock held, just before the send.
	testBeforeSend func(*bmpSession, types.IngestEvent)
}

// routerInfo is what Initiation told us about a router, and which session
// told us. sysName is the metrics label (the address when Initiation gave
// no name); name is the sysName as sent, empty if none.
type routerInfo struct {
	sysName string
	name    string
	session uint64
}

// bmpSession is one accepted BMP connection.
type bmpSession struct {
	id     uint64
	router netip.Addr
	conn   net.Conn

	// mu is held for each send on the ingest stream so that retire can
	// wait out a send in progress: once retire returns, the session puts
	// nothing more on the stream but its final session-end withdrawal.
	mu      sync.Mutex
	retired bool
	ended   bool // its session-end withdrawal has been sent
}

// retire stops a superseded session from emitting any further routes or
// withdrawals, tells the Route Table so it drops anything of the session's
// still in flight, then closes the session's socket.
func (l *Listener) retire(ctx context.Context, s *bmpSession) {
	s.mu.Lock()
	// Once its session end has gone out the session has nothing left to
	// send, and the Route Table must not start tracking it.
	if !s.ended {
		l.emit(ctx, types.IngestEvent{Session: s.id, Superseded: true})
	}
	s.retired = true
	s.mu.Unlock()
	s.conn.Close()
}

func (s *bmpSession) isRetired() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.retired
}

// NewListener creates a BMP listener that sends parsed routes and withdrawals,
// in arrival order, to ingestCh.
// If tlsCfg is non-nil, the listener accepts TLS connections; otherwise plain TCP.
func NewListener(addr string, tlsCfg *tls.Config, ingestCh chan<- types.IngestEvent, log *slog.Logger) *Listener {
	return &Listener{
		addr:     addr,
		tlsCfg:   tlsCfg,
		log:      log.With("subsystem", "bmp"),
		ingestCh: ingestCh,
		peers:    make(map[PeerKey]*Peer),
		routers:  make(map[netip.Addr]routerInfo),
		sessions: make(map[netip.Addr]*bmpSession),
	}
}

// emit sends ev on the ingest stream, blocking until there is room. It
// returns false only if ctx is cancelled first.
//
// Nothing on this stream may be dropped: a lost withdraw-all leaves every
// route of a downed peer in the Route Table for good. A full channel instead
// applies backpressure to this router's session.
func (l *Listener) emit(ctx context.Context, ev types.IngestEvent) bool {
	// select picks randomly among ready cases; check first so nothing new is
	// queued once shutdown has begun.
	if ctx.Err() != nil {
		return false
	}
	select {
	case l.ingestCh <- ev:
		return true
	case <-ctx.Done():
		return false
	}
}

// emitFrom sends ev on the ingest stream on behalf of sess, stamped with its
// session ID. It returns false, sending nothing, if sess has been superseded.
func (l *Listener) emitFrom(ctx context.Context, sess *bmpSession, ev types.IngestEvent) bool {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sess.retired {
		return false
	}
	ev.Session = sess.id
	if l.testBeforeSend != nil {
		l.testBeforeSend(sess, ev)
	}
	return l.emit(ctx, ev)
}

// register makes a new session for conn the current one for its router
// address and returns it, along with the still-open session it replaces, if
// any. Called from the accept loop, so session IDs increase in the order
// connections were accepted.
//
// Sessions are matched by source IP alone. Routers behind one NAT address
// therefore look like a single router reconnecting, and each new session
// from any of them supersedes, and closes, the others'.
func (l *Listener) register(conn net.Conn) (sess, old *bmpSession) {
	routerAddr, _ := remoteIP(conn)
	sess = &bmpSession{id: l.lastSession.Add(1), router: routerAddr.Unmap(), conn: conn}
	l.sessMu.Lock()
	old = l.sessions[sess.router]
	l.sessions[sess.router] = sess
	l.sessMu.Unlock()
	return sess, old
}

// BuildTLSConfig assembles a server-side *tls.Config from the operator-supplied
// paths. Cert and Key are required (BMP TLS is server auth). If CA is present,
// mutual TLS is enabled and client certs are required.
func BuildTLSConfig(cfg *config.TLSConfig) (*tls.Config, error) {
	if cfg == nil {
		return nil, fmt.Errorf("BMP TLS config is nil")
	}
	if cfg.Cert == "" || cfg.Key == "" {
		return nil, fmt.Errorf("BMP TLS requires both cert and key paths")
	}
	cert, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("load BMP TLS keypair: %w", err)
	}

	out := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   cfg.TLSMinVersion(),
	}

	if cfg.CA != "" {
		pem, err := os.ReadFile(cfg.CA)
		if err != nil {
			return nil, fmt.Errorf("read BMP TLS CA %q: %w", cfg.CA, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("parse BMP TLS CA %q: no PEM certificates found", cfg.CA)
		}
		out.ClientCAs = pool
		out.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return out, nil
}

// SetAllowedRouters restricts BMP connections to sources in prefixes (see
// config.ParseAllowedRouters); nil or empty accepts any source. Call before
// Listen.
func (l *Listener) SetAllowedRouters(prefixes []netip.Prefix) {
	l.allowed = prefixes
}

// Listen binds the BMP listener and returns the address it is bound to.
// Start calls it if it has not been called.
func (l *Listener) Listen() (net.Addr, error) {
	if l.listener != nil {
		return l.listener.Addr(), nil
	}
	var err error
	transport := "tcp"
	if l.tlsCfg != nil {
		l.listener, err = tls.Listen("tcp", l.addr, l.tlsCfg)
		transport = "tls"
	} else {
		l.listener, err = net.Listen("tcp", l.addr)
	}
	if err != nil {
		return nil, fmt.Errorf("BMP listen on %s: %w", l.addr, err)
	}
	bound := l.listener.Addr()
	l.log.Info("BMP listener started", "addr", bound.String(), "transport", transport,
		"allowed_routers", len(l.allowed))
	if len(l.allowed) == 0 {
		if tcp, ok := bound.(*net.TCPAddr); !ok || !tcp.IP.IsLoopback() {
			l.log.Warn("BMP listener accepts connections from any source on a non-loopback address; "+
				"set bmp.allowed-routers to the routers' addresses", "addr", bound.String())
		}
	}
	return bound, nil
}

// permits reports whether a BMP connection from addr may proceed. An
// IPv4-mapped IPv6 source is matched as IPv4.
func (l *Listener) permits(addr netip.Addr) bool {
	if len(l.allowed) == 0 {
		return true
	}
	addr = addr.Unmap()
	for _, p := range l.allowed {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// remoteIP returns conn's source address. From a dual-stack socket an IPv4
// source comes as IPv4-mapped IPv6; permits matches it as IPv4.
func remoteIP(conn net.Conn) (netip.Addr, bool) {
	if tcp, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		ap := tcp.AddrPort()
		return ap.Addr(), ap.Addr().IsValid()
	}
	ap, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	return ap.Addr(), err == nil
}

// admit decides, before anything is read from conn, whether it may become a
// BMP session. A rejected connection is logged, counted and closed.
func (l *Listener) admit(conn net.Conn) bool {
	if len(l.allowed) == 0 {
		return true
	}
	reason := metrics.RejectReasonNotAllowed
	if src, ok := remoteIP(conn); !ok {
		reason = metrics.RejectReasonBadRemoteAddr
	} else if l.permits(src) {
		return true
	}
	metrics.BMPRejectedConnectionsTotal.WithLabelValues(reason).Inc()
	l.log.Warn("BMP connection rejected: source not in bmp.allowed-routers",
		"remote", conn.RemoteAddr().String(), "reason", reason)
	conn.Close()
	return false
}

// Start begins listening for BMP connections. Blocks until ctx is cancelled.
func (l *Listener) Start(ctx context.Context) error {
	if _, err := l.Listen(); err != nil {
		return err
	}

	go func() {
		<-ctx.Done()
		l.listener.Close()
	}()

	for {
		conn, err := l.listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil // shutting down
			}
			l.log.Error("BMP accept error", "error", err)
			continue
		}
		// Before reading a byte (for TLS, before the handshake).
		if !l.admit(conn) {
			continue
		}

		sess, old := l.register(conn)
		l.log.Info("BMP session accepted", "remote", conn.RemoteAddr().String(), "session", sess.id)

		// One goroutine per BMP session (per the architecture doc)
		go l.handleSession(ctx, sess, old)
	}
}

// GetPeers returns a snapshot of all known peers.
func (l *Listener) GetPeers() []Peer {
	l.peerMu.RLock()
	defer l.peerMu.RUnlock()

	result := make([]Peer, 0, len(l.peers))
	for _, p := range l.peers {
		result = append(result, *p)
	}
	return result
}

// RouterName returns the sysName a router sent in its BMP Initiation, or ""
// if it sent none or has no session now.
func (l *Listener) RouterName(router netip.Addr) string {
	l.routerMu.RLock()
	defer l.routerMu.RUnlock()
	return l.routers[router.Unmap()].name
}

// RoutersNamed returns the routers with a session now whose Initiation
// sysName is name.
func (l *Listener) RoutersNamed(name string) []netip.Addr {
	l.routerMu.RLock()
	defer l.routerMu.RUnlock()
	var out []netip.Addr
	for addr, r := range l.routers {
		if r.name != "" && r.name == name {
			out = append(out, addr)
		}
	}
	return out
}

// GetRouterStates returns the current BMP session state for every router
// that has sent an Initiation message. Only up sessions appear (1=up);
// sessions that disconnected are removed from the map by handleSession.
func (l *Listener) GetRouterStates() map[string]int64 {
	l.routerMu.RLock()
	defer l.routerMu.RUnlock()

	result := make(map[string]int64, len(l.routers))
	for _, r := range l.routers {
		result[r.sysName] = 1
	}
	return result
}

// handleSession processes a single BMP session (one TCP connection = one
// router). old, if non-nil, is an earlier session from the same router
// address that is still open; sess supersedes it.
func (l *Listener) handleSession(ctx context.Context, sess, old *bmpSession) {
	conn := sess.conn
	defer conn.Close()
	remoteAddr := conn.RemoteAddr().String()
	sessionLog := l.log.With("router", remoteAddr, "session", sess.id)
	sessionLog.Info("BMP session started")

	// Takeover. A router opens a new session while the old socket is still
	// open when it has given up on the old one (e.g. it judged the station
	// stuck). Retire the old one before reading anything, so all of its
	// remaining output reaches the ingest stream ahead of ours and it cannot
	// deliver late updates or withdrawals over the routes we are about to
	// send; the Route Table also drops anything of its that arrives after
	// the retirement.
	//
	// "Same router" means same source IP (see register): routers sharing
	// one NAT address would supersede each other's sessions.
	if old != nil {
		sessionLog.Warn("superseding stale BMP session", "stale_session", old.id)
		l.retire(ctx, old)
	}

	defer func() {
		sessionLog.Info("BMP session ended")
		// Withdraw every route this session still owns, from all of its
		// peers. Routes a newer session has re-announced since are that
		// session's and stay. Sent even if this session was superseded.
		// emit fails only when shutting down. Under sess.mu, so a
		// takeover's retirement notice cannot follow it.
		sess.mu.Lock()
		sess.ended = true
		l.emit(ctx, types.IngestEvent{
			Withdrawal: &types.Withdrawal{SessionEnd: true},
			Session:    sess.id,
		})
		sess.mu.Unlock()

		l.sessMu.Lock()
		if l.sessions[sess.router] == sess {
			delete(l.sessions, sess.router)
		}
		l.sessMu.Unlock()

		// Clean up this session's peers. A newer session from the same
		// router may have replaced some entries already; leave those.
		l.peerMu.Lock()
		for key, p := range l.peers {
			if key.RouterAddr == sess.router && p.session == sess.id {
				delete(l.peers, key)
			}
		}
		l.peerMu.Unlock()

		// Clean up router state, unless a newer session owns it now.
		l.routerMu.Lock()
		r, ok := l.routers[sess.router]
		if ok && r.session != sess.id {
			l.routerMu.Unlock()
			return
		}
		delete(l.routers, sess.router)
		l.routerMu.Unlock()
		sysName := r.sysName
		if sysName == "" {
			sysName = remoteAddr
		}
		metrics.BMPSessionState.WithLabelValues(sysName).Set(0)
	}()

	for {
		if ctx.Err() != nil {
			return
		}
		hdrBuf := make([]byte, CommonHeaderLen)
		if _, err := io.ReadFull(conn, hdrBuf); err != nil {
			if ctx.Err() != nil {
				return
			}
			sessionLog.Error("failed to read BMP header", "error", err)
			return
		}
		hdr, err := ParseCommonHeader(hdrBuf)
		if err != nil {
			sessionLog.Error("invalid BMP header", "error", err)
			return
		}
		bodyLen := int(hdr.Length) - CommonHeaderLen
		if bodyLen < 0 || hdr.Length > MaxMessageLen {
			// The body is allocated at the length the header gives, so an
			// unchecked length let one header allocate up to 4 GB.
			sessionLog.Error("invalid BMP message length", "length", hdr.Length, "max", MaxMessageLen)
			return
		}
		body := make([]byte, bodyLen)
		if bodyLen > 0 {
			if _, err := io.ReadFull(conn, body); err != nil {
				sessionLog.Error("failed to read BMP body", "error", err)
				return
			}
		}
		l.processMessage(ctx, sessionLog, sess, hdr, body)
	}
}

// processMessage dispatches a parsed BMP message by type.
func (l *Listener) processMessage(
	ctx context.Context,
	log *slog.Logger,
	sess *bmpSession,
	hdr BMPCommonHeader,
	body []byte,
) {
	// A superseded session's router and peer state belong to its successor.
	if sess.isRetired() {
		return
	}
	routerAddr := sess.router
	switch hdr.MsgType {
	case MsgTypeInitiation:
		init, err := ParseInitiation(body)
		if err != nil {
			log.Error("failed to parse initiation", "error", err)
			return
		}
		// Store sysName for use as Prometheus label
		sysName := init.SysName
		if sysName == "" {
			sysName = routerAddr.String()
		}
		l.routerMu.Lock()
		l.routers[routerAddr] = routerInfo{sysName: sysName, name: init.SysName, session: sess.id}
		l.routerMu.Unlock()
		metrics.BMPSessionState.WithLabelValues(sysName).Set(1)
		log.Info("BMP initiation", "sysName", sysName, "sysDescr", init.SysDescr)

	case MsgTypePeerUp:
		pu, err := ParsePeerUp(body)
		if err != nil {
			log.Error("failed to parse peer up", "error", err)
			return
		}
		key := peerKey(routerAddr, pu.PerPeer)
		l.routerMu.RLock()
		sysName := l.routers[routerAddr].sysName
		l.routerMu.RUnlock()
		if sysName == "" {
			sysName = routerAddr.String()
		}
		l.peerMu.Lock()
		l.peers[key] = &Peer{
			Router:        routerAddr,
			Distinguisher: key.Distinguisher,
			PeerType:      pu.PerPeer.PeerType,
			Addr:          pu.PerPeer.PeerAddr,
			ASN:           pu.PerPeer.PeerASN,
			LocalASN:      pu.LocalASN,
			RouterID:      pu.PerPeer.PeerBGPID,
			SysName:       sysName,
			State:         "up",
			UpSince:       time.Now(),
			LastMsg:       time.Now(),
			session:       sess.id,
			addPath:       pu.AddPath,
		}
		l.peerMu.Unlock()
		metrics.BMPPeerState.WithLabelValues(sysName, routerAddr.String(), pu.PerPeer.PeerAddr.String(),
			types.FormatRD(key.Distinguisher)).Set(1)
		metrics.BMPMessagesTotal.WithLabelValues(sysName, "peer_up").Inc()
		log.Info("BMP peer up",
			"peer", pu.PerPeer.PeerAddr,
			"asn", pu.PerPeer.PeerASN,
			"local_asn", pu.LocalASN,
			"router_id", pu.PerPeer.PeerBGPID,
			"peer_distinguisher", key.Distinguisher,
			"add_path_in", pu.AddPath.In, "add_path_out", pu.AddPath.Out,
		)

	case MsgTypePeerDown:
		pd, err := ParsePeerDown(body)
		if err != nil {
			log.Error("failed to parse peer down", "error", err)
			return
		}
		key := peerKey(routerAddr, pd.PerPeer)
		l.routerMu.RLock()
		sysName := l.routers[routerAddr].sysName
		l.routerMu.RUnlock()
		if sysName == "" {
			sysName = routerAddr.String()
		}
		l.peerMu.Lock()
		if p, ok := l.peers[key]; ok {
			p.State = "down"
			p.LastMsg = time.Now()
		}
		l.peerMu.Unlock()
		metrics.BMPPeerState.WithLabelValues(sysName, routerAddr.String(), pd.PerPeer.PeerAddr.String(),
			types.FormatRD(key.Distinguisher)).Set(0)
		metrics.BMPMessagesTotal.WithLabelValues(sysName, "peer_down").Inc()
		log.Info("BMP peer down", "peer", pd.PerPeer.PeerAddr, "reason", pd.Reason)
		// Implicitly withdraw everything the peer advertised, as a real BGP
		// session going down would.
		l.emitFrom(ctx, sess, types.IngestEvent{Withdrawal: &types.Withdrawal{
			Router:            routerAddr,
			PeerDistinguisher: key.Distinguisher,
			PeerAddr:          pd.PerPeer.PeerAddr,
			WithdrawAll:       true,
		}})

	case MsgTypeRouteMonitoring:
		l.routerMu.RLock()
		sysName := l.routers[routerAddr].sysName
		l.routerMu.RUnlock()
		if sysName == "" {
			sysName = routerAddr.String()
		}
		metrics.BMPMessagesTotal.WithLabelValues(sysName, "route_monitoring").Inc()

		rm, err := ParseRouteMonitoring(body)
		if err != nil {
			log.Debug("failed to parse route monitoring", "error", err)
			return
		}
		routes, withdrawals, err := l.parseRoutes(rm, routerAddr)
		if err != nil {
			log.Debug("failed to parse BGP UPDATE", "error", err)
			return
		}
		for i := range routes {
			if !l.emitFrom(ctx, sess, types.IngestEvent{Route: &routes[i]}) {
				return
			}
		}
		for i := range withdrawals {
			if !l.emitFrom(ctx, sess, types.IngestEvent{Withdrawal: &withdrawals[i]}) {
				return
			}
		}

		// Update peer last-message time. Its route count is the route
		// table's (routetable.Table.PeerRouteCounts), not counted here: an
		// UPDATE re-announcing a route adds nothing, and withdrawals remove.
		key := peerKey(routerAddr, rm.PerPeer)
		l.peerMu.Lock()
		if p, ok := l.peers[key]; ok {
			p.LastMsg = time.Now()
		}
		l.peerMu.Unlock()

	case MsgTypeStatisticsReport:
		_, err := ParseStatsReport(body)
		if err != nil {
			log.Debug("failed to parse stats report", "error", err)
			return
		}
		// TODO: expose as Prometheus metrics

	case MsgTypeTermination:
		log.Info("BMP termination received")
		return

	default:
		log.Debug("unknown BMP message type", "type", hdr.MsgType)
	}
}

// peerKey is the peer a per-peer header describes on router.
func peerKey(router netip.Addr, pph BMPPerPeerHeader) PeerKey {
	return PeerKey{RouterAddr: router, Distinguisher: pph.Distinguisher(), PeerAddr: pph.PeerAddr}
}

// parseRoutes converts a BMP Route Monitoring message into internal Route
// objects with RAVEN's own BGP UPDATE decoder (parseBGPUpdate).
func (l *Listener) parseRoutes(rm BMPRouteMonitoring, routerAddr netip.Addr) ([]types.Route, []types.Withdrawal, error) {
	bgpData := rm.BGPUpdateData

	// BGP message: 16-byte marker + 2-byte length + 1-byte type + body
	if len(bgpData) < 19 {
		return nil, nil, fmt.Errorf("BGP message too short: %d", len(bgpData))
	}

	// Verify BGP message type is UPDATE (type 2)
	bgpMsgType := bgpData[18]
	if bgpMsgType != 2 {
		// Not an UPDATE — could be KEEPALIVE, NOTIFICATION, etc. in BMP Route Monitoring
		return nil, nil, nil
	}

	bgpLength := binary.BigEndian.Uint16(bgpData[16:18])
	if int(bgpLength) > len(bgpData) {
		return nil, nil, fmt.Errorf("BGP length %d exceeds data %d", bgpLength, len(bgpData))
	}

	// Parse the BGP UPDATE body (after the 19-byte header)
	updateBody := bgpData[19:bgpLength]

	// Look up, from the peer's Peer Up, the monitoring router's own AS on
	// this session (recorded on each route) and where ADD-PATH is in effect
	// (the decoder must know: path identifiers change the NLRI layout). A
	// peer with no Peer Up seen is taken as without ADD-PATH.
	key := peerKey(routerAddr, rm.PerPeer)
	l.peerMu.RLock()
	var localASN uint32
	var addPath AddPathState
	if p, ok := l.peers[key]; ok {
		localASN, addPath = p.LocalASN, p.addPath
	}
	l.peerMu.RUnlock()

	routes, withdrawals, err := parseBGPUpdate(updateBody, rm.PerPeer, routerAddr, localASN,
		addPath.For(rm.PerPeer.IsAdjRIBOut()))
	if err != nil {
		return nil, nil, fmt.Errorf("parse BGP UPDATE: %w", err)
	}
	return routes, withdrawals, nil
}

// parseBGPUpdate extracts routes from a BGP UPDATE message body.
//
// Handles both IPv4 NLRI (carried directly in the UPDATE body) and IPv6 NLRI
// (carried inside MP_REACH_NLRI / MP_UNREACH_NLRI path attributes per RFC 4760).
// addPath lists the address families whose NLRI carry ADD-PATH path
// identifiers (RFC 7911 §3).
func parseBGPUpdate(data []byte, pph BMPPerPeerHeader, router netip.Addr, localASN uint32, addPath AFIMask) ([]types.Route, []types.Withdrawal, error) {
	if len(data) < 4 {
		return nil, nil, nil
	}
	ribType := ribTypeOf(pph)

	// Withdrawn Routes Length, then the IPv4 withdrawn prefixes. A length
	// running past the message used to be sliced as given, which panicked
	// the session's goroutine and with it the whole process.
	withdrawnLen := int(binary.BigEndian.Uint16(data[0:2]))
	if 2+withdrawnLen+2 > len(data) {
		return nil, nil, fmt.Errorf("withdrawn routes length %d overflows a %d-byte UPDATE", withdrawnLen, len(data))
	}
	var withdrawals []types.Withdrawal
	if withdrawnLen > 0 {
		v4Withdrawals := parseNLRI(data[2:2+withdrawnLen], 4, addPath&AFIIPv4Unicast != 0)
		for _, n := range v4Withdrawals {
			withdrawals = append(withdrawals, makeWithdrawal(n, pph, router, ribType))
		}
	}

	offset := 2 + withdrawnLen

	// Total Path Attribute Length (2 bytes)
	pathAttrLen := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	pathAttrEnd := offset + int(pathAttrLen)

	if pathAttrEnd > len(data) {
		return nil, nil, fmt.Errorf("path attributes overflow: %d > %d", pathAttrEnd, len(data))
	}

	// Parse path attributes (extracts AS_PATH etc and the raw MP_REACH/MP_UNREACH bytes)
	attrs := parsePathAttributes(data[offset:pathAttrEnd], pph.Flags&PeerFlagAS2 != 0)
	offset = pathAttrEnd

	// Parse IPv4 NLRI (remaining bytes after path attributes)
	var routes []types.Route
	v4Prefixes := parseNLRI(data[offset:], 4, addPath&AFIIPv4Unicast != 0)
	for _, n := range v4Prefixes {
		routes = append(routes, makeRoute(n, attrs.nextHop, pph, router, attrs, ribType, localASN))
	}

	// NLRI carried in MP_REACH_NLRI / MP_UNREACH_NLRI (RFC 4760): IPv4 and
	// IPv6 unicast. Any other address family is counted, not decoded.
	if len(attrs.mpReach) > 0 {
		mp := parseMPReachNLRI(attrs.mpReach, addPath)
		if !mp.supported {
			countUnsupportedNLRI(mp.afi, mp.safi)
		}
		for _, n := range mp.nlri {
			routes = append(routes, makeRoute(n, mp.nextHop, pph, router, attrs, ribType, localASN))
		}
	}
	if len(attrs.mpUnreach) > 0 {
		mp := parseMPUnreachNLRI(attrs.mpUnreach, addPath)
		if !mp.supported {
			countUnsupportedNLRI(mp.afi, mp.safi)
		}
		for _, n := range mp.nlri {
			withdrawals = append(withdrawals, makeWithdrawal(n, pph, router, ribType))
		}
	}

	return routes, withdrawals, nil
}

// ribTypeOf is the RIB a Route Monitoring message reports (RFC 7854 L flag,
// RFC 8671 O flag): Adj-RIB-In or Adj-RIB-Out, pre- or post-policy.
func ribTypeOf(pph BMPPerPeerHeader) types.RIBType {
	switch {
	case pph.IsAdjRIBOut() && pph.IsPostPolicy():
		return types.AdjRIBOutPost
	case pph.IsAdjRIBOut():
		return types.AdjRIBOutPre
	case pph.IsPostPolicy():
		return types.AdjRIBInPost
	}
	return types.AdjRIBInPre
}

func countUnsupportedNLRI(afi uint16, safi uint8) {
	metrics.BMPUnsupportedNLRITotal.WithLabelValues(strconv.Itoa(int(afi)), strconv.Itoa(int(safi))).Inc()
}

// makeRoute constructs a types.Route from an NLRI entry, next hop, and
// extracted path attributes.
func makeRoute(n nlri, nextHop netip.Addr, pph BMPPerPeerHeader, router netip.Addr, attrs pathAttrs, ribType types.RIBType, localASN uint32) types.Route {
	return types.Route{
		Timestamp:         pph.Timestamp,
		Router:            router,
		PeerDistinguisher: pph.Distinguisher(),
		PeerType:          pph.PeerType,
		PeerAddr:          pph.PeerAddr,
		PeerASN:           pph.PeerASN,
		PathID:            n.pathID,
		LocalASN:          localASN,
		RouterID:          pph.PeerBGPID,
		Prefix:            n.prefix,
		ASPath:            attrs.asPath,
		ASPathRaw:         attrs.asPathRaw,
		Origin:            types.OriginType(attrs.origin),
		NextHop:           nextHop,
		Communities:       attrs.communities,
		LargeCommunities:  attrs.largeCommunities,
		RIBType:           ribType,
	}
}

// makeWithdrawal constructs a types.Withdrawal for an NLRI entry.
func makeWithdrawal(n nlri, pph BMPPerPeerHeader, router netip.Addr, ribType types.RIBType) types.Withdrawal {
	return types.Withdrawal{
		Router:            router,
		PeerDistinguisher: pph.Distinguisher(),
		PeerAddr:          pph.PeerAddr,
		Prefix:            n.prefix,
		PathID:            n.pathID,
		RIBType:           ribType,
	}
}

// nlri is one NLRI entry: a prefix and, with ADD-PATH, its path identifier.
type nlri struct {
	prefix netip.Prefix
	pathID uint32
}

// parseNLRI iterates length-prefixed NLRI entries. addrLen is 4 for IPv4 NLRI
// or 16 for IPv6 NLRI; it bounds how many bytes are read into the address slot.
// With addPath each entry starts with a 4-byte path identifier (RFC 7911 §3).
func parseNLRI(data []byte, addrLen int, addPath bool) []nlri {
	var out []nlri
	off := 0
	maxBits := addrLen * 8
	for off < len(data) {
		var pathID uint32
		if addPath {
			if off+4 > len(data) {
				break
			}
			pathID = binary.BigEndian.Uint32(data[off : off+4])
			off += 4
			if off >= len(data) {
				break
			}
		}
		pLen := int(data[off])
		off++
		if pLen > maxBits {
			break
		}
		pBytes := (pLen + 7) / 8
		if off+pBytes > len(data) {
			break
		}
		buf := make([]byte, addrLen)
		copy(buf, data[off:off+pBytes])
		off += pBytes
		addr, ok := netip.AddrFromSlice(buf)
		if !ok {
			continue
		}
		out = append(out, nlri{prefix: netip.PrefixFrom(addr.Unmap(), pLen), pathID: pathID})
	}
	return out
}

// mpNLRI is a decoded MP_REACH_NLRI or MP_UNREACH_NLRI attribute.
type mpNLRI struct {
	afi       uint16
	safi      uint8
	supported bool       // an address family RAVEN decodes (IPv4 or IPv6 unicast)
	nextHop   netip.Addr // MP_REACH only
	nlri      []nlri
}

// mpFamily returns the NLRI address length and ADD-PATH bit for a supported
// (afi, safi): IPv4 or IPv6 unicast.
func mpFamily(afi uint16, safi uint8) (addrLen int, bit AFIMask, ok bool) {
	switch {
	case afi == 1 && safi == 1:
		return 4, AFIIPv4Unicast, true
	case afi == 2 && safi == 1:
		return 16, AFIIPv6Unicast, true
	}
	return 0, 0, false
}

// parseMPReachNLRI parses an MP_REACH_NLRI attribute payload (RFC 4760 §3).
// Layout:
//
//	AFI(2) | SAFI(1) | NH Len(1) | NH(variable) | Reserved(1) | NLRI(variable)
//
// IPv4 and IPv6 unicast are decoded, each with its own ADD-PATH setting. The
// next hop is IPv4 (4 bytes, IPv4 NLRI only) or IPv6 (16 bytes global, or 32
// with a link-local RAVEN drops); an IPv6 next hop for IPv4 NLRI is RFC 8950.
// Other address families come back unsupported. A malformed attribute (too
// short, next hop running past it) yields no NLRI.
func parseMPReachNLRI(data []byte, addPath AFIMask) mpNLRI {
	if len(data) < 5 {
		return mpNLRI{supported: true}
	}
	mp := mpNLRI{afi: binary.BigEndian.Uint16(data[0:2]), safi: data[2]}
	addrLen, bit, ok := mpFamily(mp.afi, mp.safi)
	if !ok {
		return mp
	}
	mp.supported = true
	nhLen := int(data[3])
	if 4+nhLen+1 > len(data) {
		return mp
	}
	switch {
	case nhLen == 4 && mp.afi == 1:
		mp.nextHop = netip.AddrFrom4([4]byte(data[4:8]))
	case nhLen == 16 || nhLen == 32:
		mp.nextHop = netip.AddrFrom16([16]byte(data[4:20]))
	}
	mp.nlri = parseNLRI(data[4+nhLen+1:], addrLen, addPath&bit != 0) // skip the reserved byte
	return mp
}

// parseMPUnreachNLRI parses an MP_UNREACH_NLRI attribute payload (RFC 4760 §4).
// Layout:
//
//	AFI(2) | SAFI(1) | Withdrawn NLRI(variable)
//
// IPv4 and IPv6 unicast are decoded; other address families come back
// unsupported.
func parseMPUnreachNLRI(data []byte, addPath AFIMask) mpNLRI {
	if len(data) < 3 {
		return mpNLRI{supported: true}
	}
	mp := mpNLRI{afi: binary.BigEndian.Uint16(data[0:2]), safi: data[2]}
	addrLen, bit, ok := mpFamily(mp.afi, mp.safi)
	if !ok {
		return mp
	}
	mp.supported = true
	mp.nlri = parseNLRI(data[3:], addrLen, addPath&bit != 0)
	return mp
}

// pathAttrs collects the path-attribute fields RAVEN cares about, plus the raw
// MP_REACH/MP_UNREACH bodies for downstream multiprotocol NLRI parsing.
type pathAttrs struct {
	asPath           []uint32
	asPathRaw        []types.ASSegment
	origin           uint8
	nextHop          netip.Addr // IPv4 NEXT_HOP only; MP next hops live in MP_REACH
	communities      []types.Community
	largeCommunities []types.LargeCommunity
	mpReach          []byte // MP_REACH_NLRI body (attr type 14)
	mpUnreach        []byte // MP_UNREACH_NLRI body (attr type 15)
}

// BGP path attribute type codes RAVEN reads.
const (
	attrOrigin           = 1
	attrASPath           = 2
	attrNextHop          = 3
	attrCommunities      = 8
	attrMPReach          = 14
	attrMPUnreach        = 15
	attrAS4Path          = 17 // RFC 6793
	attrLargeCommunities = 32
)

// asTrans is AS_TRANS (RFC 6793): the 2-octet stand-in for a 4-octet AS.
const asTrans = 23456

// parsePathAttributes walks the path attributes and extracts the fields
// RAVEN cares about: AS_PATH, ORIGIN, NEXT_HOP, COMMUNITIES, MP_REACH_NLRI,
// MP_UNREACH_NLRI, LARGE_COMMUNITIES and AS4_PATH.
//
// as2 is the per-peer header's A flag (RFC 7854 §4.2): the peer session uses
// 2-octet AS numbers, so AS_PATH holds 2-octet ASNs (4-octet ones as
// AS_TRANS) and AS4_PATH, if present, carries the 4-octet path to merge
// (RFC 6793 §4.2.3). Without it AS_PATH holds 4-octet ASNs and AS4_PATH is
// ignored, as a 4-octet speaker must.
func parsePathAttributes(data []byte, as2 bool) pathAttrs {
	var out pathAttrs
	var as4Path []types.ASSegment
	offset := 0
	for offset < len(data) {
		if offset+2 > len(data) {
			break
		}

		flags := data[offset]
		attrType := data[offset+1]
		offset += 2

		// Attribute length: 1 byte or 2 bytes depending on Extended Length flag
		var attrLen int
		if flags&0x10 != 0 { // Extended Length
			if offset+2 > len(data) {
				break
			}
			attrLen = int(binary.BigEndian.Uint16(data[offset : offset+2]))
			offset += 2
		} else {
			if offset+1 > len(data) {
				break
			}
			attrLen = int(data[offset])
			offset++
		}

		if offset+attrLen > len(data) {
			break
		}

		attrData := data[offset : offset+attrLen]
		offset += attrLen

		switch attrType {
		case attrOrigin:
			if len(attrData) >= 1 {
				out.origin = attrData[0]
			}

		case attrASPath:
			asnLen := 4
			if as2 {
				asnLen = 2
			}
			out.asPathRaw = parseASPath(attrData, asnLen)

		case attrAS4Path:
			if as2 {
				as4Path = parseASPath(attrData, 4)
			}

		case attrNextHop:
			if len(attrData) == 4 {
				out.nextHop = netip.AddrFrom4([4]byte(attrData))
			}

		case attrCommunities:
			for i := 0; i+4 <= len(attrData); i += 4 {
				out.communities = append(out.communities, types.Community{
					High: binary.BigEndian.Uint16(attrData[i : i+2]),
					Low:  binary.BigEndian.Uint16(attrData[i+2 : i+4]),
				})
			}

		case attrMPReach:
			out.mpReach = attrData

		case attrMPUnreach:
			out.mpUnreach = attrData

		case attrLargeCommunities:
			for i := 0; i+12 <= len(attrData); i += 12 {
				out.largeCommunities = append(out.largeCommunities, types.LargeCommunity{
					GlobalAdmin: binary.BigEndian.Uint32(attrData[i : i+4]),
					LocalData1:  binary.BigEndian.Uint32(attrData[i+4 : i+8]),
					LocalData2:  binary.BigEndian.Uint32(attrData[i+8 : i+12]),
				})
			}
		}
	}

	if as4Path != nil {
		out.asPathRaw = mergeAS4Path(out.asPathRaw, as4Path)
	}
	out.asPath = flattenASPath(out.asPathRaw)
	return out
}

// parseASPath parses AS_PATH (or AS4_PATH) attribute data with asnLen-byte
// AS numbers (2 or 4) into its segments. A segment running past the
// attribute ends the parse; the segments before it are kept.
func parseASPath(data []byte, asnLen int) []types.ASSegment {
	var raw []types.ASSegment
	offset := 0
	for offset+2 <= len(data) {
		segType := types.ASSegmentType(data[offset])
		segLen := int(data[offset+1])
		offset += 2
		if offset+segLen*asnLen > len(data) {
			break
		}
		seg := types.ASSegment{Type: segType, ASNs: make([]uint32, segLen)}
		for i := 0; i < segLen; i++ {
			if asnLen == 2 {
				seg.ASNs[i] = uint32(binary.BigEndian.Uint16(data[offset : offset+2]))
			} else {
				seg.ASNs[i] = binary.BigEndian.Uint32(data[offset : offset+4])
			}
			offset += asnLen
		}
		raw = append(raw, seg)
	}
	return raw
}

// flattenASPath lists the path's AS numbers in order. AS_SET members are
// included (expanded); so are confederation segments.
func flattenASPath(segs []types.ASSegment) []uint32 {
	var flat []uint32
	for _, s := range segs {
		flat = append(flat, s.ASNs...)
	}
	return flat
}

// asPathCount is the number of AS numbers in a path as RFC 6793 §4.2.3
// counts them (RFC 4271 §9.1.2.2): each AS_SEQUENCE member counts one, an
// AS_SET counts one, confederation segments count none.
func asPathCount(segs []types.ASSegment) int {
	n := 0
	for _, s := range segs {
		switch s.Type {
		case types.ASSegmentSequence:
			n += len(s.ASNs)
		case types.ASSegmentSet:
			n++
		}
	}
	return n
}

// mergeAS4Path reconstructs the AS path from AS_PATH and AS4_PATH received
// over a 2-octet session (RFC 6793 §4.2.3). If AS_PATH has fewer AS numbers
// than AS4_PATH, AS4_PATH is ignored. Otherwise the result is the leading
// part of AS_PATH, as many AS numbers and segments as make up the
// difference, followed by AS4_PATH, so it has as many AS numbers as AS_PATH:
// the AS_TRANS stand-ins in AS_PATH's tail are replaced by the real 4-octet
// ASNs. Confederation segments in AS4_PATH, which a speaker must not send
// there, are dropped.
func mergeAS4Path(asPath, as4Path []types.ASSegment) []types.ASSegment {
	var as4 []types.ASSegment
	for _, s := range as4Path {
		if s.Type == types.ASSegmentSequence || s.Type == types.ASSegmentSet {
			as4 = append(as4, s)
		}
	}
	need := asPathCount(asPath) - asPathCount(as4)
	if need < 0 {
		return asPath
	}
	var out []types.ASSegment
	for _, s := range asPath {
		if need == 0 {
			break
		}
		switch s.Type {
		case types.ASSegmentSequence:
			k := min(need, len(s.ASNs))
			out = append(out, types.ASSegment{Type: s.Type, ASNs: s.ASNs[:k:k]})
			need -= k
		case types.ASSegmentSet:
			out = append(out, s)
			need--
		default: // confederation segments count none; keep them in place
			out = append(out, s)
		}
	}
	return append(out, as4...)
}
