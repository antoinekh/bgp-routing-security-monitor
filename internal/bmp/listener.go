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
// told us.
type routerInfo struct {
	sysName string
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
	routerAddr, _ := netip.ParseAddrPort(conn.RemoteAddr().String())
	sess = &bmpSession{id: l.lastSession.Add(1), router: routerAddr.Addr(), conn: conn}
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
	reason := "not_allowed"
	if src, ok := remoteIP(conn); !ok {
		reason = "bad_remote_addr"
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
		if bodyLen < 0 {
			sessionLog.Error("invalid BMP message length", "length", hdr.Length)
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
		l.routers[routerAddr] = routerInfo{sysName: sysName, session: sess.id}
		l.routerMu.Unlock()
		metrics.BMPSessionState.WithLabelValues(sysName).Set(1)
		log.Info("BMP initiation", "sysName", sysName, "sysDescr", init.SysDescr)

	case MsgTypePeerUp:
		pu, err := ParsePeerUp(body)
		if err != nil {
			log.Error("failed to parse peer up", "error", err)
			return
		}
		key := PeerKey{RouterAddr: routerAddr, PeerAddr: pu.PerPeer.PeerAddr}
		l.routerMu.RLock()
		sysName := l.routers[routerAddr].sysName
		l.routerMu.RUnlock()
		if sysName == "" {
			sysName = routerAddr.String()
		}
		l.peerMu.Lock()
		l.peers[key] = &Peer{
			Addr:     pu.PerPeer.PeerAddr,
			ASN:      pu.PerPeer.PeerASN,
			LocalASN: pu.LocalASN,
			RouterID: pu.PerPeer.PeerBGPID,
			SysName:  sysName,
			State:    "up",
			UpSince:  time.Now(),
			LastMsg:  time.Now(),
			session:  sess.id,
		}
		l.peerMu.Unlock()
		metrics.BMPPeerState.WithLabelValues(sysName, pu.PerPeer.PeerAddr.String()).Set(1)
		metrics.BMPMessagesTotal.WithLabelValues(sysName, "peer_up").Inc()
		log.Info("BMP peer up",
			"peer", pu.PerPeer.PeerAddr,
			"asn", pu.PerPeer.PeerASN,
			"local_asn", pu.LocalASN,
			"router_id", pu.PerPeer.PeerBGPID,
		)

	case MsgTypePeerDown:
		pd, err := ParsePeerDown(body)
		if err != nil {
			log.Error("failed to parse peer down", "error", err)
			return
		}
		key := PeerKey{RouterAddr: routerAddr, PeerAddr: pd.PerPeer.PeerAddr}
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
		metrics.BMPPeerState.WithLabelValues(sysName, pd.PerPeer.PeerAddr.String()).Set(0)
		metrics.BMPMessagesTotal.WithLabelValues(sysName, "peer_down").Inc()
		log.Info("BMP peer down", "peer", pd.PerPeer.PeerAddr, "reason", pd.Reason)
		// Implicitly withdraw everything the peer advertised, as a real BGP
		// session going down would.
		l.emitFrom(ctx, sess, types.IngestEvent{Withdrawal: &types.Withdrawal{
			PeerAddr:    pd.PerPeer.PeerAddr,
			WithdrawAll: true,
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
		key := PeerKey{RouterAddr: routerAddr, PeerAddr: rm.PerPeer.PeerAddr}
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

// parseRoutes converts a BMP Route Monitoring message into internal Route objects
// using GoBGP's BGP UPDATE parser.
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

	// Look up the monitoring router's own AS on this session, learned from
	// the Peer Up message's Sent OPEN (see ParsePeerUp), and record it on
	// each route.
	key := PeerKey{RouterAddr: routerAddr, PeerAddr: rm.PerPeer.PeerAddr}
	l.peerMu.RLock()
	var localASN uint32
	if p, ok := l.peers[key]; ok {
		localASN = p.LocalASN
	}
	l.peerMu.RUnlock()

	routes, withdrawals, err := parseBGPUpdate(updateBody, rm.PerPeer, localASN)
	if err != nil {
		return nil, nil, fmt.Errorf("parse BGP UPDATE: %w", err)
	}
	return routes, withdrawals, nil
}

// parseBGPUpdate extracts routes from a BGP UPDATE message body.
//
// Handles both IPv4 NLRI (carried directly in the UPDATE body) and IPv6 NLRI
// (carried inside MP_REACH_NLRI / MP_UNREACH_NLRI path attributes per RFC 4760).
func parseBGPUpdate(data []byte, pph BMPPerPeerHeader, localASN uint32) ([]types.Route, []types.Withdrawal, error) {
	if len(data) < 4 {
		return nil, nil, nil
	}
	ribType := types.AdjRIBInPre
	if pph.IsPostPolicy() {
		ribType = types.AdjRIBInPost
	}

	// Parse IPv4 withdrawn prefixes (top of UPDATE body)
	withdrawnLen := binary.BigEndian.Uint16(data[0:2])
	var withdrawals []types.Withdrawal
	if withdrawnLen > 0 {
		v4Withdrawals := parseNLRI(data[2:2+int(withdrawnLen)], 4)
		for _, p := range v4Withdrawals {
			withdrawals = append(withdrawals, types.Withdrawal{
				PeerAddr: pph.PeerAddr,
				Prefix:   p,
				RIBType:  ribType,
			})
		}
	}

	offset := 2 + int(withdrawnLen)
	if offset+2 > len(data) {
		return nil, withdrawals, nil
	}

	// Total Path Attribute Length (2 bytes)
	pathAttrLen := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	pathAttrEnd := offset + int(pathAttrLen)

	if pathAttrEnd > len(data) {
		return nil, nil, fmt.Errorf("path attributes overflow: %d > %d", pathAttrEnd, len(data))
	}

	// Parse path attributes (extracts AS_PATH etc and the raw MP_REACH/MP_UNREACH bytes)
	attrs := parsePathAttributes(data[offset:pathAttrEnd])
	offset = pathAttrEnd

	// Parse IPv4 NLRI (remaining bytes after path attributes)
	var routes []types.Route
	v4Prefixes := parseNLRI(data[offset:], 4)
	for _, prefix := range v4Prefixes {
		routes = append(routes, makeRoute(prefix, attrs.nextHop, pph, attrs, ribType, localASN))
	}

	// Parse IPv6 NLRI carried inside MP_REACH_NLRI (AFI=2, SAFI=1)
	if len(attrs.mpReach) > 0 {
		nh, prefixes := parseMPReachNLRI(attrs.mpReach)
		for _, p := range prefixes {
			routes = append(routes, makeRoute(p, nh, pph, attrs, ribType, localASN))
		}
	}

	// Parse IPv6 withdrawals carried inside MP_UNREACH_NLRI (AFI=2, SAFI=1)
	if len(attrs.mpUnreach) > 0 {
		prefixes := parseMPUnreachNLRI(attrs.mpUnreach)
		for _, p := range prefixes {
			withdrawals = append(withdrawals, types.Withdrawal{
				PeerAddr: pph.PeerAddr,
				Prefix:   p,
				RIBType:  ribType,
			})
		}
	}

	return routes, withdrawals, nil
}

// makeRoute constructs a types.Route from a prefix, next hop, and extracted path attributes.
func makeRoute(prefix netip.Prefix, nextHop netip.Addr, pph BMPPerPeerHeader, attrs pathAttrs, ribType types.RIBType, localASN uint32) types.Route {
	return types.Route{
		Timestamp:        pph.Timestamp,
		PeerAddr:         pph.PeerAddr,
		PeerASN:          pph.PeerASN,
		LocalASN:         localASN,
		RouterID:         pph.PeerBGPID,
		Prefix:           prefix,
		ASPath:           attrs.asPath,
		ASPathRaw:        attrs.asPathRaw,
		Origin:           types.OriginType(attrs.origin),
		NextHop:          nextHop,
		Communities:      attrs.communities,
		LargeCommunities: attrs.largeCommunities,
		RIBType:          ribType,
	}
}

// parseNLRI iterates length-prefixed NLRI entries. addrLen is 4 for IPv4 NLRI
// or 16 for IPv6 NLRI; it bounds how many bytes are read into the address slot.
func parseNLRI(data []byte, addrLen int) []netip.Prefix {
	var out []netip.Prefix
	off := 0
	maxBits := addrLen * 8
	for off < len(data) {
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
		out = append(out, netip.PrefixFrom(addr.Unmap(), pLen))
	}
	return out
}

// parseMPReachNLRI parses an MP_REACH_NLRI attribute payload (RFC 4760 §3).
// Layout:
//
//	AFI(2) | SAFI(1) | NH Len(1) | NH(variable) | Reserved(1) | NLRI(variable)
//
// Only AFI=2 (IPv6) SAFI=1 (unicast) is handled; other combinations are ignored.
// For IPv6 the next hop is 16 bytes (global) or 32 bytes (global + link-local);
// the link-local is dropped — RAVEN only records the global address.
func parseMPReachNLRI(data []byte) (netip.Addr, []netip.Prefix) {
	if len(data) < 5 {
		return netip.Addr{}, nil
	}
	afi := binary.BigEndian.Uint16(data[0:2])
	safi := data[2]
	if afi != 2 || safi != 1 {
		return netip.Addr{}, nil
	}
	nhLen := int(data[3])
	if 4+nhLen+1 > len(data) {
		return netip.Addr{}, nil
	}
	var nextHop netip.Addr
	if nhLen >= 16 {
		// Take the first 16 bytes as the global next hop. Per RFC 2545, a
		// 32-byte field carries the link-local in bytes 16..31; we drop it.
		if addr, ok := netip.AddrFromSlice(data[4 : 4+16]); ok {
			nextHop = addr
		}
	}
	nlriStart := 4 + nhLen + 1 // skip reserved byte
	if nlriStart > len(data) {
		return nextHop, nil
	}
	return nextHop, parseNLRI(data[nlriStart:], 16)
}

// parseMPUnreachNLRI parses an MP_UNREACH_NLRI attribute payload (RFC 4760 §4).
// Layout:
//
//	AFI(2) | SAFI(1) | Withdrawn NLRI(variable)
//
// Only AFI=2 (IPv6) SAFI=1 (unicast) is handled.
func parseMPUnreachNLRI(data []byte) []netip.Prefix {
	if len(data) < 3 {
		return nil
	}
	afi := binary.BigEndian.Uint16(data[0:2])
	safi := data[2]
	if afi != 2 || safi != 1 {
		return nil
	}
	return parseNLRI(data[3:], 16)
}

// pathAttrs collects the path-attribute fields RAVEN cares about, plus the raw
// MP_REACH/MP_UNREACH bodies for downstream multiprotocol NLRI parsing.
type pathAttrs struct {
	asPath           []uint32
	asPathRaw        []types.ASSegment
	origin           uint8
	nextHop          netip.Addr // IPv4 NEXT_HOP only; IPv6 next hop lives in MP_REACH
	communities      []types.Community
	largeCommunities []types.LargeCommunity
	mpReach          []byte // MP_REACH_NLRI body (attr type 14)
	mpUnreach        []byte // MP_UNREACH_NLRI body (attr type 15)
}

// parsePathAttributes walks the path attributes and extracts the fields
// RAVEN cares about: AS_PATH, ORIGIN, NEXT_HOP, COMMUNITIES, MP_REACH_NLRI,
// MP_UNREACH_NLRI.
func parsePathAttributes(data []byte) pathAttrs {
	var out pathAttrs
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
		case 1: // ORIGIN
			if len(attrData) >= 1 {
				out.origin = attrData[0]
			}

		case 2: // AS_PATH
			out.asPath, out.asPathRaw = parseASPath(attrData)

		case 3: // NEXT_HOP (IPv4)
			if len(attrData) == 4 {
				if addr, ok := netip.AddrFromSlice(attrData); ok {
					out.nextHop = addr
				}
			}

		case 8: // COMMUNITIES
			for i := 0; i+4 <= len(attrData); i += 4 {
				out.communities = append(out.communities, types.Community{
					High: binary.BigEndian.Uint16(attrData[i : i+2]),
					Low:  binary.BigEndian.Uint16(attrData[i+2 : i+4]),
				})
			}

		case 14: // MP_REACH_NLRI (RFC 4760)
			out.mpReach = attrData

		case 15: // MP_UNREACH_NLRI (RFC 4760)
			out.mpUnreach = attrData

		case 32: // LARGE_COMMUNITIES
			for i := 0; i+12 <= len(attrData); i += 12 {
				out.largeCommunities = append(out.largeCommunities, types.LargeCommunity{
					GlobalAdmin: binary.BigEndian.Uint32(attrData[i : i+4]),
					LocalData1:  binary.BigEndian.Uint32(attrData[i+4 : i+8]),
					LocalData2:  binary.BigEndian.Uint32(attrData[i+8 : i+12]),
				})
			}
		}
	}

	return out
}

// parseASPath parses the AS_PATH attribute data into flat and raw forms.
func parseASPath(data []byte) (flat []uint32, raw []types.ASSegment) {
	offset := 0
	for offset < len(data) {
		if offset+2 > len(data) {
			break
		}

		segType := types.ASSegmentType(data[offset])
		segLen := int(data[offset+1])
		offset += 2

		if offset+segLen*4 > len(data) {
			break
		}

		seg := types.ASSegment{
			Type: segType,
			ASNs: make([]uint32, segLen),
		}

		for i := 0; i < segLen; i++ {
			seg.ASNs[i] = binary.BigEndian.Uint32(data[offset : offset+4])
			offset += 4
		}

		raw = append(raw, seg)

		// Flatten: AS_SEQUENCE segments contribute to the flat path
		// AS_SET segments are expanded (all ASNs included)
		flat = append(flat, seg.ASNs...)
	}

	return
}
