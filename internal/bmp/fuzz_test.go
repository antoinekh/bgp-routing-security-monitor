package bmp

import (
	"encoding/binary"
	"net/netip"
	"reflect"
	"runtime"
	"testing"

	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// Fuzz targets for RAVEN's BMP and BGP decoding, which reads untrusted input
// from routers. Each checks three properties on every input:
//
//   - no panic;
//   - allocation bounded by the input, not by length fields in it: total
//     allocation stays under allocBound(len(input));
//   - nothing read past the message: decoding the input from a slice with
//     hidden bytes after it (len < cap) gives exactly what decoding an exact
//     copy gives.
//
// Run with `make fuzz` (FUZZTIME per target, default 5m). Inputs that fail
// are saved under testdata/fuzz/<Target>/ and replayed by every `go test`.

// allocBound is the most a decode may allocate for n input bytes: a route
// (a few hundred bytes) per NLRI byte at worst, plus a fixed allowance.
func allocBound(n int) uint64 { return uint64(n)*1024 + 1<<20 }

// checkAlloc runs f and fails if it allocated more than allocBound(n).
func checkAlloc(t *testing.T, n int, f func()) {
	t.Helper()
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	f()
	runtime.ReadMemStats(&m1)
	if got := m1.TotalAlloc - m0.TotalAlloc; got > allocBound(n) {
		t.Fatalf("decoding %d bytes allocated %d bytes (bound %d): a length field is trusted", n, got, allocBound(n))
	}
}

// withHiddenTail returns data in a slice whose capacity runs into 64 bytes of
// garbage: a decoder that reslices past len would see them.
func withHiddenTail(data []byte) []byte {
	buf := make([]byte, len(data), len(data)+64)
	copy(buf, data)
	tail := buf[len(data) : len(data)+64]
	for i := range tail {
		tail[i] = 0xa5
	}
	return buf
}

func exactCopy(data []byte) []byte { return append([]byte(nil), data...) }

// sameOnBothSlices decodes data as an exact copy and with a hidden tail and
// fails if the results differ.
func sameOnBothSlices[T any](t *testing.T, data []byte, decode func([]byte) T) T {
	t.Helper()
	var exact, tailed T
	checkAlloc(t, len(data), func() { exact = decode(exactCopy(data)) })
	tailed = decode(withHiddenTail(data))
	if !reflect.DeepEqual(exact, tailed) {
		t.Fatalf("decode read past the message:\n exact  %+v\n tailed %+v", exact, tailed)
	}
	return exact
}

type updateResult struct {
	Routes      []types.Route
	Withdrawals []types.Withdrawal
	Err         string
}

func decodeUpdate(data []byte, flags uint8, addPath AFIMask) updateResult {
	pph := BMPPerPeerHeader{Flags: flags, PeerAddr: netip.MustParseAddr("80.81.194.180"), PeerASN: 64501}
	rs, ws, err := parseBGPUpdate(data, pph, netip.MustParseAddr("192.0.2.1"), 64500, addPath)
	r := updateResult{Routes: rs, Withdrawals: ws}
	if err != nil {
		r.Err = err.Error()
	}
	return r
}

// FuzzDecodeUpdate fuzzes the BGP UPDATE decoder: withdrawn routes, path
// attributes (AS_PATH and AS4_PATH with 2- and 4-octet ASNs, communities,
// MP_REACH_NLRI / MP_UNREACH_NLRI for every AFI/SAFI) and NLRI, with
// ADD-PATH on and off per address family and every per-peer flag.
func FuzzDecodeUpdate(f *testing.F) {
	p, v6 := netip.MustParsePrefix("1.1.1.0/24"), netip.MustParsePrefix("2001:db8:1::/48")
	for _, seed := range [][]byte{
		updateBody(false, false, []pathNLRI{{0, p}}, []pathNLRI{{0, p}}, []pathNLRI{{0, v6}}),
		updateBody(true, true, []pathNLRI{{3, p}}, []pathNLRI{{1, p}, {2, p}}, []pathNLRI{{7, v6}}),
		updateWithAttrs(append(mpReachAttr(1, 1, []byte{192, 0, 2, 1}, encodeNLRI(false, pathNLRI{0, p})),
			mpUnreachAttr(1, 1, encodeNLRI(true, pathNLRI{9, p}))...)),
		updateWithAttrs(mpReachAttr(1, 1, netip.MustParseAddr("2001:db8::fe").AsSlice(), encodeNLRI(false, pathNLRI{0, p}))),
		updateWithAttrs(mpReachAttr(1, 128, make([]byte, 12), []byte{0x70, 0, 0, 1})),
		updateWithAttrs(append(asPathAttr(2, 2, seq(64500, asTrans)), asPathAttr(17, 4, seq(4200000001))...)),
		updateWithAttrs([]byte{0xc0, 8, 4, 0xfd, 0xe8, 0, 1, 0xc0, 32, 12, 0, 0, 0xfd, 0xe8, 0, 0, 0, 1, 0, 0, 0, 2}),
	} {
		for _, flags := range []uint8{0, PeerFlagAS2, PeerFlagAdjRIBOut | PeerFlagPostPolicy} {
			f.Add(seed, flags, uint8(0))
			f.Add(seed, flags, uint8(AFIIPv4Unicast|AFIIPv6Unicast))
		}
	}
	f.Fuzz(func(t *testing.T, data []byte, flags, addPath uint8) {
		r := sameOnBothSlices(t, data, func(b []byte) updateResult {
			return decodeUpdate(b, flags, AFIMask(addPath)&(AFIIPv4Unicast|AFIIPv6Unicast))
		})
		for _, rt := range r.Routes {
			if !rt.Prefix.IsValid() || rt.Prefix != rt.Prefix.Masked() && rt.Prefix.Bits() < 0 {
				t.Fatalf("decoded an invalid prefix %v", rt.Prefix)
			}
		}
	})
}

type peerUpResult struct {
	PeerUp BMPPeerUp
	Err    string
	Open   openInfo
	OErr   string
}

// FuzzPeerUpOpen fuzzes Peer Up parsing, including the embedded Sent and
// Received OPENs (classic and RFC 9072 extended optional parameters, the
// 4-octet AS and ADD-PATH capabilities), and OPEN parsing on its own.
func FuzzPeerUpOpen(f *testing.F) {
	peer := netip.MustParseAddr("80.81.194.180")
	for _, msg := range [][]byte{
		peerUpMsg(peer),
		peerUpWithOpens(peer, 0, openMsg(64500), openMsg(64501)),
		peerUpWithOpens(peer, 0x0000fde8_00000064, openMsg(64500, addPathCap(withSR(v4uni, 3), withSR(v6uni, 1))),
			openMsg(64501, addPathCap(withSR(v4uni, 3)), []byte{bgpCap4ByteASN, 4, 0xfa, 0x56, 0xea, 0x01})),
		peerUpWithOpens(peer, 0, extendedOpen(64500, addPathCap(withSR(v4uni, 1))), extendedOpen(64501)),
	} {
		f.Add(msg[CommonHeaderLen:])
	}
	f.Add(openMsg(64500, addPathCap(withSR(v4uni, 3))))
	f.Add(extendedOpen(23456, []byte{bgpCap4ByteASN, 4, 0, 1, 0, 0}))
	f.Fuzz(func(t *testing.T, data []byte) {
		sameOnBothSlices(t, data, func(b []byte) peerUpResult {
			var r peerUpResult
			pu, err := ParsePeerUp(b)
			r.PeerUp = pu
			if err != nil {
				r.Err = err.Error()
			}
			o, err := parseOpen(b)
			r.Open = o
			if err != nil {
				r.OErr = err.Error()
			}
			return r
		})
	})
}

type messageResult struct {
	Header BMPCommonHeader
	Parsed any
	Err    string
	Update updateResult
}

// decodeMessage decodes one BMP message as the listener does: the common
// header, then the body by message type, and a Route Monitoring's UPDATE
// with ADD-PATH as given.
func decodeMessage(data []byte, addPath AFIMask) messageResult {
	var r messageResult
	hdr, err := ParseCommonHeader(data)
	r.Header = hdr
	if err != nil {
		r.Err = err.Error()
		return r
	}
	if hdr.Length > MaxMessageLen || int(hdr.Length) > len(data) {
		r.Err = "length"
		return r
	}
	body := data[CommonHeaderLen:hdr.Length]
	setErr := func(err error) {
		if err != nil {
			r.Err = err.Error()
		}
	}
	switch hdr.MsgType {
	case MsgTypeInitiation:
		v, err := ParseInitiation(body)
		r.Parsed = v
		setErr(err)
	case MsgTypePeerUp:
		v, err := ParsePeerUp(body)
		r.Parsed = v
		setErr(err)
	case MsgTypePeerDown:
		v, err := ParsePeerDown(body)
		r.Parsed = v
		setErr(err)
	case MsgTypeStatisticsReport:
		v, err := ParseStatsReport(body)
		r.Parsed = v
		setErr(err)
	case MsgTypeRouteMonitoring:
		rm, err := ParseRouteMonitoring(body)
		r.Parsed = rm
		setErr(err)
		if err == nil && len(rm.BGPUpdateData) >= 19 && rm.BGPUpdateData[18] == 2 {
			n := int(binary.BigEndian.Uint16(rm.BGPUpdateData[16:18]))
			if n >= 19 && n <= len(rm.BGPUpdateData) {
				r.Update = decodeUpdate(rm.BGPUpdateData[19:n], rm.PerPeer.Flags, addPath)
			}
		}
	}
	return r
}

// FuzzBMPMessage fuzzes whole BMP messages: the common header, per-peer
// header, and each message type's body, Route Monitoring through the UPDATE
// decoder.
func FuzzBMPMessage(f *testing.F) {
	peer := netip.MustParseAddr("80.81.194.180")
	p := netip.MustParsePrefix("1.1.1.0/24")
	stats := append(perPeerHeader(peer), 0, 0, 0, 2, 0, 1, 0, 4, 0, 0, 0, 9, 0, 7, 0, 8, 0, 0, 0, 0, 0, 0, 0, 3)
	for _, msg := range [][]byte{
		initiationMsg("br1.nyc"),
		peerUpMsg(peer),
		peerUpWithOpens(peer, 0, openMsg(64500, addPathCap(withSR(v4uni, 1))), openMsg(64501, addPathCap(withSR(v4uni, 2)))),
		routeMonitoringMsg(peer, p, netip.MustParsePrefix("8.8.8.0/24")),
		routeMonitoringRD(peer, 0x0000fde8_00000064, updateBody(true, false, nil, []pathNLRI{{1, p}, {2, p}}, nil)),
		bmpMsg(MsgTypePeerDown, peerDownBody(peer)),
		bmpMsg(MsgTypeStatisticsReport, stats),
		bmpMsg(MsgTypeTermination, nil),
	} {
		f.Add(msg, uint8(0))
		f.Add(msg, uint8(AFIIPv4Unicast))
	}
	f.Fuzz(func(t *testing.T, data []byte, addPath uint8) {
		sameOnBothSlices(t, data, func(b []byte) messageResult {
			return decodeMessage(b, AFIMask(addPath)&(AFIIPv4Unicast|AFIIPv6Unicast))
		})
	})
}
