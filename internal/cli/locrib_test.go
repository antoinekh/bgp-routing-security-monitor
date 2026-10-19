package cli

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// raven status lists postures in one fixed order, best first, and RIBs in
// RIBType order; it used map order, which changed from run to run. Its header
// says which RIBs the default view adds up.
func TestStatusRouteTableOrder(t *testing.T) {
	byPosture := map[string]uint64{
		"origin-invalid": 1, "path-suspect": 2, "unverified": 3, "origin-only": 4, "path-only": 5, "secured": 6,
		"some-new-posture": 7,
	}
	byRIB := map[string]uint64{"loc-rib": 10, "adj-rib-out-pre": 1, "adj-rib-in-pre": 11, "adj-rib-in-post": 3}
	var want string
	for i := 0; i < 20; i++ {
		var b bytes.Buffer
		printRouteTable(&b, 21, []string{"adj-rib-in-pre", "loc-rib"}, byPosture, byRIB)
		if i == 0 {
			want = b.String()
		} else if b.String() != want {
			t.Fatalf("run %d printed\n%s\nrun 0 printed\n%s", i, b.String(), want)
		}
	}
	var order []string
	for _, line := range strings.Split(want, "\n") {
		if f := strings.Fields(line); strings.HasPrefix(line, "  ") && len(f) == 2 {
			order = append(order, f[0])
		}
	}
	wantOrder := []string{"secured", "path-only", "origin-only", "unverified", "path-suspect", "origin-invalid", "some-new-posture",
		"adj-rib-in-pre", "adj-rib-in-post", "loc-rib", "adj-rib-out-pre"}
	if strings.Join(order, " ") != strings.Join(wantOrder, " ") {
		t.Errorf("order %v, want %v", order, wantOrder)
	}
	if !strings.HasPrefix(want, "Route Table: 21 routes in the default view (adj-rib-in-pre + loc-rib)\n") {
		t.Errorf("header: %q", strings.SplitN(want, "\n", 2)[0])
	}
}

// raven peers and raven status show a Loc-RIB instance, whose address is
// zero, as loc-rib (with the RD of a VRF instance, not its table name), and
// every peer's type.
func TestPeersShowLocRIB(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `[
			{"router":"192.0.2.1","router_name":"rr1","peer_type":"loc-rib","table_name":"global","addr":"0.0.0.0","asn":65000,"state":"up","route_count":3},
			{"router":"192.0.2.1","router_name":"rr1","peer_type":"loc-rib","table_name":"red","peer_distinguisher":"65000L:1","addr":"0.0.0.0","asn":65000,"state":"up","route_count":1},
			{"router":"192.0.2.2","router_name":"rr2","peer_type":"global","addr":"10.0.12.1","asn":65000,"state":"up","route_count":3}]`)
	}))
	defer srv.Close()
	out := runCLI(t, srv, "peers")
	for _, want := range [][]string{
		{"rr1", "loc-rib", "loc-rib", "65000"},
		{"rr1", "loc-rib", "rd", "65000L:1", "loc-rib", "65000"},
		{"rr2", "10.0.12.1", "global", "65000"},
	} {
		found := false
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(strings.Join(strings.Fields(line), " ")+" ", strings.Join(want, " ")+" ") {
				found = true
			}
		}
		if !found {
			t.Errorf("no row starting %v in:\n%s", want, out)
		}
	}
}

// raven routes shows the RIB of each route, and "-" for the peer of a
// Loc-RIB route.
func TestRoutesShowRIB(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `[
			{"prefix":"1.1.1.0/24","router":"192.0.2.1","peer":"0.0.0.0","peer_type":"loc-rib","rib":"loc-rib","origin_asn":13335,"rov":"Valid","aspa":"Unknown","posture":"origin-only"},
			{"prefix":"1.1.1.0/24","router":"192.0.2.2","peer":"10.0.12.1","peer_type":"global","rib":"adj-rib-in-pre","origin_asn":13335,"rov":"Valid","aspa":"Unknown","posture":"origin-only"}]`)
	}))
	defer srv.Close()
	out := runCLI(t, srv, "routes")
	for _, want := range []string{"1.1.1.0/24 192.0.2.1 - loc-rib AS13335", "1.1.1.0/24 192.0.2.2 10.0.12.1 adj-rib-in-pre AS13335"} {
		if !strings.Contains(strings.Join(strings.Fields(out), " "), want) {
			t.Errorf("no %q in:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "RIB") {
		t.Errorf("no RIB column:\n%s", out)
	}
}

// raven audit sends --rib (adj-rib-in-pre by default) and reports an API
// error instead of an empty report.
func TestAuditRIBFlag(t *testing.T) {
	var got url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Query()
		if got.Get("rib") == "bogus" {
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, `{"error":"unknown RIB \"bogus\""}`)
			return
		}
		io.WriteString(w, `{"router_id":"192.0.2.1","rib":"`+got.Get("rib")+`"}`)
	}))
	defer srv.Close()
	runCLI(t, srv, "audit", "--router", "192.0.2.1")
	if got.Get("rib") != "adj-rib-in-pre" {
		t.Errorf("default rib %q, want adj-rib-in-pre", got.Get("rib"))
	}
	if out := runCLI(t, srv, "audit", "--router", "192.0.2.1", "--rib", "loc-rib"); !strings.Contains(out, "RIB:           loc-rib") {
		t.Errorf("rib loc-rib: sent %q; output:\n%s", got.Get("rib"), out)
	}
	rootCmd.SetArgs([]string{"audit", "--router", "192.0.2.1", "--rib", "bogus", "--address", strings.TrimPrefix(srv.URL, "http://")})
	err := rootCmd.Execute()
	rootCmd.SetArgs(nil)
	if err == nil || !strings.Contains(err.Error(), "unknown RIB") {
		t.Errorf("unknown rib: err %v, want the API's error", err)
	}
	runCLI(t, srv, "audit", "--router", "192.0.2.1", "--rib", "adj-rib-in-pre") // flags outlive a run
}

// raven check takes the neighbor AS of a Loc-RIB route from its path, after
// any leading copy of the router's own AS (its peer_asn); a Loc-RIB instance
// is never taken for a BGP neighbor.
func TestCheckNeighborASNLocRIB(t *testing.T) {
	for _, tc := range []struct {
		name string
		r    stealthyRoute
		want uint32
	}{
		{"BGP peer", stealthyRoute{RIB: "adj-rib-in-pre", PeerASN: 64510, ASPath: []uint32{64510, 64500}}, 64510},
		{"Loc-RIB", stealthyRoute{RIB: "loc-rib", PeerASN: 65000, ASPath: []uint32{64510, 64500}}, 64510},
		{"Loc-RIB, own AS first (FRR 10.2)", stealthyRoute{RIB: "loc-rib", PeerASN: 65000, ASPath: []uint32{65000, 64510, 64500}}, 64510},
		{"Loc-RIB, locally originated", stealthyRoute{RIB: "loc-rib", PeerASN: 65000}, 0},
	} {
		if got := tc.r.neighborASN(); got != tc.want {
			t.Errorf("%s: neighborASN = %d, want %d", tc.name, got, tc.want)
		}
	}
	best := stealthyRoute{RIB: "loc-rib", PeerASN: 65000, OriginASN: 64500, ASPath: []uint32{65000, 64510, 64500}}
	if got := labelFor(64510, best); got != "expected peer" {
		t.Errorf("labelFor(neighbor) = %q, want expected peer", got)
	}
	if got := labelFor(65000, best); got != "ATTACKER" {
		t.Errorf("labelFor(the router's own AS) = %q, want ATTACKER: it is not the neighbor", got)
	}
	peers := []stealthyPeer{{Addr: "0.0.0.0", PeerType: "loc-rib", ASN: 65000}, {Addr: "10.0.1.2", PeerType: "global", ASN: 64510}}
	if p := lookupPeer(peers, "0.0.0.0"); p != nil {
		t.Errorf("lookupPeer found the Loc-RIB instance %+v", p)
	}
	if p := lookupPeer(peers, "10.0.1.2"); p == nil || p.ASN != 64510 {
		t.Errorf("lookupPeer(10.0.1.2) = %+v, want the BGP peer", p)
	}
}
