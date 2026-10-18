package bmp

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"
)

const bmpVersion = 3

// ParseCommonHeader parses the 6-byte BMP common header.
// Returns the header and any error.
func ParseCommonHeader(data []byte) (BMPCommonHeader, error) {
	if len(data) < CommonHeaderLen {
		return BMPCommonHeader{}, fmt.Errorf("BMP common header too short: %d bytes", len(data))
	}

	h := BMPCommonHeader{
		Version: data[0],
		Length:  binary.BigEndian.Uint32(data[1:5]),
		MsgType: data[5],
	}

	if h.Version != bmpVersion {
		return h, fmt.Errorf("unsupported BMP version %d (expected %d)", h.Version, bmpVersion)
	}

	if h.Length < CommonHeaderLen {
		return h, fmt.Errorf("BMP message length %d is less than common header size", h.Length)
	}

	return h, nil
}

// Distinguisher returns the Peer Distinguisher as a number: zero for a
// global-instance peer, the VRF's route distinguisher for an RD-instance one.
func (h *BMPPerPeerHeader) Distinguisher() uint64 {
	return binary.BigEndian.Uint64(h.PeerDistinguisher[:])
}

// ParsePerPeerHeader parses the 42-byte per-peer header from the given data.
func ParsePerPeerHeader(data []byte) (BMPPerPeerHeader, error) {
	if len(data) < PerPeerHeaderLen {
		return BMPPerPeerHeader{}, fmt.Errorf("per-peer header too short: %d bytes", len(data))
	}

	h := BMPPerPeerHeader{
		PeerType: data[0],
		Flags:    data[1],
	}

	copy(h.PeerDistinguisher[:], data[2:10])

	// Peer address: 16 bytes (10..25). IPv4 is in the last 4 bytes.
	var addrBytes [16]byte
	copy(addrBytes[:], data[10:26])

	if h.IsIPv6() {
		addr, ok := netip.AddrFromSlice(addrBytes[:])
		if !ok {
			return h, fmt.Errorf("invalid IPv6 peer address")
		}
		h.PeerAddr = addr
	} else {
		// IPv4 is stored in the last 4 bytes of the 16-byte field
		addr, ok := netip.AddrFromSlice(addrBytes[12:16])
		if !ok {
			return h, fmt.Errorf("invalid IPv4 peer address")
		}
		h.PeerAddr = addr
	}

	// Peer AS: bytes 26..29
	h.PeerASN = binary.BigEndian.Uint32(data[26:30])

	// Peer BGP ID: bytes 30..33 (IPv4 router ID)
	bgpID, ok := netip.AddrFromSlice(data[30:34])
	if !ok {
		return h, fmt.Errorf("invalid BGP ID")
	}
	h.PeerBGPID = bgpID

	// Timestamp: bytes 34..37 (seconds) + 38..41 (microseconds)
	sec := binary.BigEndian.Uint32(data[34:38])
	usec := binary.BigEndian.Uint32(data[38:42])
	h.Timestamp = time.Unix(int64(sec), int64(usec)*1000)

	return h, nil
}

// ParseInitiation parses a BMP Initiation message body (after common header).
func ParseInitiation(data []byte) (BMPInitiation, error) {
	init := BMPInitiation{}
	offset := 0

	for offset+4 <= len(data) {
		tlvType := binary.BigEndian.Uint16(data[offset : offset+2])
		tlvLen := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		offset += 4

		if offset+int(tlvLen) > len(data) {
			return init, fmt.Errorf("initiation TLV overflows message: type=%d len=%d", tlvType, tlvLen)
		}

		val := string(data[offset : offset+int(tlvLen)])
		offset += int(tlvLen)

		switch tlvType {
		case InitTLVString:
			init.Info = val
		case InitTLVSysDescr:
			init.SysDescr = val
		case InitTLVSysName:
			init.SysName = val
		}
	}

	return init, nil
}

// ParseRouteMonitoring parses a BMP Route Monitoring message body.
// It extracts the per-peer header and returns the raw BGP UPDATE PDU
// for GoBGP to parse.
func ParseRouteMonitoring(data []byte) (BMPRouteMonitoring, error) {
	pph, err := ParsePerPeerHeader(data)
	if err != nil {
		return BMPRouteMonitoring{}, fmt.Errorf("route monitoring per-peer header: %w", err)
	}

	bgpData := data[PerPeerHeaderLen:]

	// BGP message has a 19-byte header (16 marker + 2 length + 1 type)
	// We pass the entire BGP message to GoBGP for parsing
	if len(bgpData) < 19 {
		return BMPRouteMonitoring{}, fmt.Errorf("BGP message too short: %d bytes", len(bgpData))
	}

	return BMPRouteMonitoring{
		PerPeer:       pph,
		BGPUpdateData: bgpData,
	}, nil
}

// ParsePeerUp parses a BMP Peer Up message body.
func ParsePeerUp(data []byte) (BMPPeerUp, error) {
	pph, err := ParsePerPeerHeader(data)
	if err != nil {
		return BMPPeerUp{}, fmt.Errorf("peer up per-peer header: %w", err)
	}

	body := data[PerPeerHeaderLen:]
	if len(body) < 20 {
		return BMPPeerUp{}, fmt.Errorf("peer up body too short: %d bytes", len(body))
	}

	pu := BMPPeerUp{PerPeer: pph}

	// Local address: 16 bytes
	if pph.IsIPv6() {
		addr, ok := netip.AddrFromSlice(body[0:16])
		if !ok {
			return pu, fmt.Errorf("invalid IPv6 local address")
		}
		pu.LocalAddr = addr
	} else {
		addr, ok := netip.AddrFromSlice(body[12:16])
		if !ok {
			return pu, fmt.Errorf("invalid IPv4 local address")
		}
		pu.LocalAddr = addr
	}

	// Local port: bytes 16..17, Remote port: bytes 18..19
	pu.LocalPort = binary.BigEndian.Uint16(body[16:18])
	pu.RemotePort = binary.BigEndian.Uint16(body[18:20])

	// Sent OPEN Message: the BGP OPEN the monitored router sent to this
	// peer. Its My Autonomous System field (or the 4-octet ASN capability,
	// if present) is the monitoring router's own AS on this session. The
	// Received OPEN, from the peer, follows it.
	//
	// A malformed/missing embedded OPEN is not fatal to Peer Up processing:
	// LocalASN stays 0 (unknown) and ADD-PATH is taken as off.
	sent, err := parseOpen(body[20:])
	if err != nil {
		return pu, nil
	}
	pu.LocalASN = sent.asn
	if sent.length >= len(body[20:]) {
		return pu, nil
	}
	recv, err := parseOpen(body[20+sent.length:])
	if err != nil {
		return pu, nil
	}
	pu.AddPath = negotiateAddPath(sent.addPath, recv.addPath)
	return pu, nil
}

// negotiateAddPath works out, from the ADD-PATH capabilities in the OPEN the
// monitored router sent (local) and the one it received from the peer, where
// path identifiers are in use (RFC 7911 §4). Updates from the peer (the
// Adj-RIB-In) carry them for an address family if the router said it can
// receive and the peer said it can send; updates to the peer (Adj-RIB-Out)
// if the router can send and the peer can receive.
func negotiateAddPath(local, peer map[afiSafi]uint8) AddPathState {
	var st AddPathState
	for fam, bit := range map[afiSafi]AFIMask{{afi: 1, safi: 1}: AFIIPv4Unicast, {afi: 2, safi: 1}: AFIIPv6Unicast} {
		if local[fam]&addPathReceive != 0 && peer[fam]&addPathSend != 0 {
			st.In |= bit
		}
		if local[fam]&addPathSend != 0 && peer[fam]&addPathReceive != 0 {
			st.Out |= bit
		}
	}
	return st
}

// BGP message header: 16-byte marker + 2-byte length + 1-byte type.
const bgpHeaderLen = 19
const bgpMsgTypeOpen = 1

// BGP OPEN optional parameter / capability codes (RFC 4271, RFC 5492,
// RFC 6793, RFC 7911).
const (
	bgpOptParamCapabilities uint8 = 2
	bgpCap4ByteASN          uint8 = 65
	bgpCapAddPath           uint8 = 69
)

// ADD-PATH capability Send/Receive values (RFC 7911 §4): 1 receive, 2 send,
// 3 both.
const (
	addPathReceive uint8 = 1
	addPathSend    uint8 = 2
)

// afiSafi is an address family (AFI) and subsequent address family (SAFI).
type afiSafi struct {
	afi  uint16
	safi uint8
}

// openInfo is what RAVEN reads from a BGP OPEN.
type openInfo struct {
	length  int    // the whole message, header included
	asn     uint32 // My AS, or the 4-octet AS capability if present
	addPath map[afiSafi]uint8
}

// parseOpen reads a BGP OPEN message: its length, the AS number (the 2-byte
// "My Autonomous System" field, overridden by the 4-octet AS Number
// capability, RFC 6793, when present, as routers do when AS_TRANS (23456)
// is in the fixed-width field), and the ADD-PATH capability's Send/Receive
// value per address family.
func parseOpen(data []byte) (openInfo, error) {
	var o openInfo
	if len(data) < bgpHeaderLen {
		return o, fmt.Errorf("OPEN message too short: %d bytes", len(data))
	}
	if data[18] != bgpMsgTypeOpen {
		return o, fmt.Errorf("expected BGP OPEN (type %d), got type %d", bgpMsgTypeOpen, data[18])
	}

	msgLen := int(binary.BigEndian.Uint16(data[16:18]))
	if msgLen < bgpHeaderLen || msgLen > len(data) {
		msgLen = len(data) // tolerate a truncated/misreported length
	}
	o.length = msgLen
	body := data[bgpHeaderLen:msgLen]

	// Fixed OPEN fields: Version(1) + My AS(2) + Hold Time(2) + BGP ID(4) + Opt Parm Len(1)
	if len(body) < 10 {
		return o, fmt.Errorf("OPEN body too short: %d bytes", len(body))
	}
	o.asn = uint32(binary.BigEndian.Uint16(body[1:3]))
	optParmLen := int(body[9])

	optParams := body[10:]
	if optParmLen > len(optParams) {
		optParmLen = len(optParams)
	}
	optParams = optParams[:optParmLen]

	// Walk optional parameters for the Capabilities parameter, then walk
	// capabilities for the 4-octet AS Number and ADD-PATH capabilities.
	off := 0
	for off+2 <= len(optParams) {
		paramType := optParams[off]
		paramLen := int(optParams[off+1])
		off += 2
		if off+paramLen > len(optParams) {
			break
		}
		paramVal := optParams[off : off+paramLen]
		off += paramLen

		if paramType != bgpOptParamCapabilities {
			continue
		}

		capOff := 0
		for capOff+2 <= len(paramVal) {
			capCode := paramVal[capOff]
			capLen := int(paramVal[capOff+1])
			capOff += 2
			if capOff+capLen > len(paramVal) {
				break
			}
			capVal := paramVal[capOff : capOff+capLen]
			capOff += capLen

			switch {
			case capCode == bgpCap4ByteASN && capLen == 4:
				o.asn = binary.BigEndian.Uint32(capVal)
			case capCode == bgpCapAddPath:
				for i := 0; i+4 <= len(capVal); i += 4 {
					if o.addPath == nil {
						o.addPath = make(map[afiSafi]uint8)
					}
					fam := afiSafi{afi: binary.BigEndian.Uint16(capVal[i : i+2]), safi: capVal[i+2]}
					o.addPath[fam] = capVal[i+3]
				}
			}
		}
	}

	return o, nil
}

// ParsePeerDown parses a BMP Peer Down message body.
func ParsePeerDown(data []byte) (BMPPeerDown, error) {
	pph, err := ParsePerPeerHeader(data)
	if err != nil {
		return BMPPeerDown{}, fmt.Errorf("peer down per-peer header: %w", err)
	}

	body := data[PerPeerHeaderLen:]
	if len(body) < 1 {
		return BMPPeerDown{}, fmt.Errorf("peer down body too short")
	}

	return BMPPeerDown{
		PerPeer: pph,
		Reason:  body[0],
	}, nil
}

// ParseStatsReport parses a BMP Statistics Report message body.
func ParseStatsReport(data []byte) (BMPStatsReport, error) {
	pph, err := ParsePerPeerHeader(data)
	if err != nil {
		return BMPStatsReport{}, fmt.Errorf("stats report per-peer header: %w", err)
	}

	body := data[PerPeerHeaderLen:]
	if len(body) < 4 {
		return BMPStatsReport{}, fmt.Errorf("stats report body too short")
	}

	count := binary.BigEndian.Uint32(body[0:4])
	counters := make(map[uint16]uint64, count)
	offset := 4

	for i := uint32(0); i < count; i++ {
		if offset+4 > len(body) {
			break
		}
		statType := binary.BigEndian.Uint16(body[offset : offset+2])
		statLen := binary.BigEndian.Uint16(body[offset+2 : offset+4])
		offset += 4

		if offset+int(statLen) > len(body) {
			break
		}

		switch statLen {
		case 4:
			counters[statType] = uint64(binary.BigEndian.Uint32(body[offset : offset+4]))
		case 8:
			counters[statType] = binary.BigEndian.Uint64(body[offset : offset+8])
		}
		offset += int(statLen)
	}

	return BMPStatsReport{
		PerPeer:  pph,
		Counters: counters,
	}, nil
}
