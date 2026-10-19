package bmp

import (
	"net/netip"
	"time"
)

// BMP Message Types (RFC 7854 §4.1)
const (
	MsgTypeRouteMonitoring  uint8 = 0
	MsgTypeStatisticsReport uint8 = 1
	MsgTypePeerDown         uint8 = 2
	MsgTypePeerUp           uint8 = 3
	MsgTypeInitiation       uint8 = 4
	MsgTypeTermination      uint8 = 5
	MsgTypeRouteMirroring   uint8 = 6
)

// BMP Peer Types (RFC 7854 §4.2, RFC 9069 §4.1)
const (
	PeerTypeGlobal  uint8 = 0
	PeerTypeRDLocal uint8 = 1
	PeerTypeLocal   uint8 = 2
	// PeerTypeLocRIB is a Loc-RIB instance (RFC 9069): the routes the
	// monitored router selected, not those of one BGP peer.
	PeerTypeLocRIB uint8 = 3
)

// BMP Peer Flags (RFC 7854 §4.2), for peer types 0 to 2.
const (
	PeerFlagIPv6       uint8 = 0x80 // Bit 0: 1 = IPv6, 0 = IPv4
	PeerFlagPostPolicy uint8 = 0x40 // Bit 1: 1 = Post-Policy, 0 = Pre-Policy
	PeerFlagAS2        uint8 = 0x20 // Bit 2: 1 = AS_PATH uses 2-byte ASNs
	PeerFlagAdjRIBOut  uint8 = 0x10 // Bit 3: 1 = Adj-RIB-Out (RFC 8671)
)

// PeerFlagLocRIBFiltered is the only flag of a Loc-RIB per-peer header (RFC
// 9069 §4.2), the F flag: the Loc-RIB sent is filtered, not complete. It is
// the bit types 0 to 2 use for V (IPv6), and reading it as V took a filtered
// Loc-RIB's zero peer address for IPv6.
const PeerFlagLocRIBFiltered uint8 = 0x80

// BMP Initiation TLV Types (RFC 7854 §4.3)
const (
	InitTLVString   uint16 = 0 // Free-form string
	InitTLVSysDescr uint16 = 1 // sysDescr
	InitTLVSysName  uint16 = 2 // sysName
)

// BMP Common Header length: 5 bytes (Version + MsgLength + MsgType)
const CommonHeaderLen = 6 // 1 (version) + 4 (length) + 1 (type)

// MaxMessageLen bounds a BMP message RAVEN accepts. The largest legitimate
// ones, a Route Monitoring with an RFC 8654 extended (65,535-byte) BGP
// message, or a Peer Up with two OPENs and information TLVs, are far below
// it; a session sending a longer one is closed.
const MaxMessageLen = 1 << 20

// BMP Per-Peer Header length: 42 bytes
const PerPeerHeaderLen = 42

// BMPCommonHeader represents the 6-byte common header on every BMP message.
type BMPCommonHeader struct {
	Version uint8
	Length  uint32
	MsgType uint8
}

// BMPPerPeerHeader represents the 42-byte per-peer header (RFC 7854 §4.2).
type BMPPerPeerHeader struct {
	PeerType          uint8
	Flags             uint8
	PeerDistinguisher [8]byte
	PeerAddr          netip.Addr
	PeerASN           uint32
	PeerBGPID         netip.Addr // Router ID as IPv4
	Timestamp         time.Time
}

// IsLocRIB reports whether the header describes the router's Loc-RIB (RFC
// 9069) rather than one of its BGP peers. Its peer address is zero and its
// Peer AS is the router's own AS (§4.1).
func (h *BMPPerPeerHeader) IsLocRIB() bool {
	return h.PeerType == PeerTypeLocRIB
}

// IsLocRIBFiltered reports a Loc-RIB header's F flag (RFC 9069 §4.2).
func (h *BMPPerPeerHeader) IsLocRIBFiltered() bool {
	return h.IsLocRIB() && h.Flags&PeerFlagLocRIBFiltered != 0
}

// The flag tests below are for peer types 0 to 2. A Loc-RIB header defines
// only the F flag, so for it they all report false.

// IsIPv6 returns true if the peer address is IPv6.
func (h *BMPPerPeerHeader) IsIPv6() bool {
	return !h.IsLocRIB() && h.Flags&PeerFlagIPv6 != 0
}

// IsPostPolicy returns true if this is Post-Policy Adj-RIB-In.
func (h *BMPPerPeerHeader) IsPostPolicy() bool {
	return !h.IsLocRIB() && h.Flags&PeerFlagPostPolicy != 0
}

// IsAS2 returns true if the AS_PATH uses 2-byte ASNs.
func (h *BMPPerPeerHeader) IsAS2() bool {
	return !h.IsLocRIB() && h.Flags&PeerFlagAS2 != 0
}

// IsAdjRIBOut returns true if this is Adj-RIB-Out (RFC 8671).
func (h *BMPPerPeerHeader) IsAdjRIBOut() bool {
	return !h.IsLocRIB() && h.Flags&PeerFlagAdjRIBOut != 0
}

// BMPInitiation represents a BMP Initiation message (Type 4).
type BMPInitiation struct {
	SysName  string
	SysDescr string
	Info     string // free-form string TLV
}

// BMPPeerUp represents a BMP Peer Up message (Type 3).
type BMPPeerUp struct {
	PerPeer    BMPPerPeerHeader
	LocalAddr  netip.Addr
	LocalPort  uint16
	RemotePort uint16
	// LocalASN is the monitored router's own AS on this session, taken from
	// the Sent OPEN message's My Autonomous System field (overridden by the
	// 4-octet AS Number capability, RFC 6793, when present). Zero if the
	// embedded OPEN message could not be parsed.
	LocalASN uint32
	// AddPath is where ADD-PATH path identifiers are in use on this
	// session, from the Sent and Received OPEN messages.
	AddPath AddPathState
	// TableName is the VRF/Table Name information TLV (RFC 9069 §5.1,
	// type 3) of a Loc-RIB instance's Peer Up, e.g. "global" or a VRF
	// name; "" if none.
	TableName string
}

// AFIMask is a set of address families.
type AFIMask uint8

const (
	AFIIPv4Unicast AFIMask = 1 << iota
	AFIIPv6Unicast
)

// AddPathState says, per address family, whether a peer's BGP updates carry
// ADD-PATH path identifiers (RFC 7911): In for the updates the monitored
// router receives from the peer (Adj-RIB-In), Out for those it sends it
// (Adj-RIB-Out). Decoding NLRI with the wrong setting misreads every prefix.
type AddPathState struct {
	In, Out AFIMask
}

// For returns the address families with path identifiers in updates of the
// given direction.
func (a AddPathState) For(adjRIBOut bool) AFIMask {
	if adjRIBOut {
		return a.Out
	}
	return a.In
}

// BMPPeerDown represents a BMP Peer Down message (Type 2).
type BMPPeerDown struct {
	PerPeer BMPPerPeerHeader
	Reason  uint8
}

// BMPRouteMonitoring represents a BMP Route Monitoring message (Type 0).
// The BGP UPDATE is decoded separately (parseBGPUpdate).
type BMPRouteMonitoring struct {
	PerPeer       BMPPerPeerHeader
	BGPUpdateData []byte // raw BGP UPDATE PDU
}

// BMPStatsReport represents a BMP Statistics Report (Type 1).
type BMPStatsReport struct {
	PerPeer  BMPPerPeerHeader
	Counters map[uint16]uint64
}

// Peer is the runtime state RAVEN maintains per BMP peer session.
type Peer struct {
	// Router is the monitored router the peer is on: its BMP session's
	// source address. Distinguisher and PeerType are from the per-peer
	// header.
	Router        netip.Addr
	Distinguisher uint64
	PeerType      uint8
	Addr          netip.Addr
	ASN           uint32
	LocalASN      uint32 // monitoring router's own AS on this session (from Peer Up's Sent OPEN, or a Loc-RIB header's Peer AS); 0 if unknown
	RouterID      netip.Addr
	// TableName is a Loc-RIB instance's VRF/Table Name, from its Peer Up;
	// "" if none was sent (a Loc-RIB registered without a Peer Up has none).
	TableName string
	SysName   string
	SysDescr  string
	State     string // "up" or "down"
	UpSince   time.Time
	LastMsg   time.Time

	// MalformedInput is set when an UPDATE from the peer was malformed in
	// a way RFC 7606 answers with a session reset (MalformedReason says
	// which, a raven_bmp_malformed_updates_total reason; MalformedAt when
	// first). RAVEN withdrew what it could parse and expects the router's
	// Peer Down; until then its routes for the peer may be incomplete. A
	// new Peer Up clears it.
	MalformedInput  bool
	MalformedReason string
	MalformedAt     time.Time

	session uint64       // ID of the BMP session whose Peer Up created this entry
	addPath AddPathState // from Peer Up
}

// PeerKey uniquely identifies a BMP peer.
type PeerKey struct {
	RouterAddr    netip.Addr // the BMP session source (router)
	Distinguisher uint64     // the peer's instance on that router (0 = global)
	PeerAddr      netip.Addr // the BGP peer on that router
}
