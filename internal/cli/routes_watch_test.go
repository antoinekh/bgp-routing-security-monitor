package cli

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

// runCLI runs the raven CLI with args against srv and returns its stdout.
func runCLI(t *testing.T, srv *httptest.Server, args ...string) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	rootCmd.SetArgs(append(args, "--address", strings.TrimPrefix(srv.URL, "http://")))
	runErr := rootCmd.Execute()
	os.Stdout = stdout
	w.Close()
	out, _ := io.ReadAll(r)
	rootCmd.SetArgs(nil)
	if runErr != nil {
		t.Fatalf("raven %v: %v", args, runErr)
	}
	return string(out)
}

// raven watch sends every filter it is given; it used to send only --posture.
func TestWatchSendsAllFilters(t *testing.T) {
	var got url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Query()
	}))
	defer srv.Close()
	runCLI(t, srv, "watch", "--prefix", "1.1.1.0/24", "--origin-asn", "13335",
		"--peer", "80.81.194.180", "--posture", "secured", "--router", "br1.nyc")
	want := url.Values{"prefix": {"1.1.1.0/24"}, "origin-asn": {"13335"}, "peer": {"80.81.194.180"},
		"posture": {"secured"}, "router": {"br1.nyc"}}
	if got.Encode() != want.Encode() {
		t.Errorf("watch query = %q, want %q", got.Encode(), want.Encode())
	}
	runCLI(t, srv, "watch", "--prefix", "", "--origin-asn", "0", "--peer", "", "--posture", "", "--router", "")
}

// raven routes sends --peer with --prefix, and --format wide shows the
// failing ASPA hop as C->P, or "-" when there is none.
func TestRoutesPeerAndFailingHop(t *testing.T) {
	var got url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Query()
		io.WriteString(w, `[
 {"prefix":"145.102.136.0/22","peer":"80.81.194.180","origin_asn":1199,"rov":"Valid","aspa":"Invalid",
  "posture":"path-suspect","aspa_procedure":"upstream","aspa_procedure_source":"default",
  "aspa_failing_hop":{"customer_asn":1199,"provider_asn":65000}},
 {"prefix":"1.1.1.0/24","peer":"80.81.194.180","origin_asn":13335,"rov":"Valid","aspa":"Valid",
  "posture":"secured","aspa_procedure":"upstream","aspa_procedure_source":"default"}]`)
	}))
	defer srv.Close()
	out := runCLI(t, srv, "routes", "--prefix", "1.1.1.0/24", "--peer", "80.81.194.180", "--router", "192.0.2.1", "--format", "wide")
	if got.Get("prefix") != "1.1.1.0/24" || got.Get("peer") != "80.81.194.180" || got.Get("router") != "192.0.2.1" {
		t.Errorf("routes query = %q, want prefix, peer and router", got.Encode())
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 || !strings.HasSuffix(strings.TrimSpace(lines[0]), "FAILING HOP") ||
		!strings.HasSuffix(strings.TrimSpace(lines[1]), "1199->65000") || !strings.HasSuffix(strings.TrimSpace(lines[2]), "-") {
		t.Errorf("wide output:\n%s", out)
	}
	runCLI(t, srv, "routes", "--prefix", "", "--peer", "", "--router", "", "--format", "table")
}

// raven status and raven peers show each peer per router, with its count
// there; two routers with the same route-server peer are two rows.
func TestStatusAndPeersShowRouter(t *testing.T) {
	peers := `[{"router":"192.0.2.1","router_name":"br1.nyc","addr":"80.81.194.180","asn":6695,"state":"up","route_count":12},
 {"router":"192.0.2.2","addr":"80.81.194.180","asn":6695,"state":"up","route_count":34},
 {"router":"192.0.2.1","router_name":"br1.nyc","peer_distinguisher":"65000:100","addr":"80.81.194.180","asn":6695,"state":"up","route_count":5}]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/status" {
			io.WriteString(w, `{"version":"t","uptime":"1s","bmp_peers":`+peers+`}`)
			return
		}
		io.WriteString(w, peers)
	}))
	defer srv.Close()
	for _, cmd := range []string{"status", "peers"} {
		out := runCLI(t, srv, cmd)
		if !strings.Contains(out, "ROUTER") {
			t.Errorf("%s has no ROUTER column:\n%s", cmd, out)
		}
		for _, row := range [][]string{{"br1.nyc", "80.81.194.180", "12"}, {"192.0.2.2", "80.81.194.180", "34"}, {"br1.nyc", "80.81.194.180 rd 65000:100", "5"}} {
			found := false
			for _, line := range strings.Split(out, "\n") {
				f := strings.Join(strings.Fields(line), " ")
				if strings.HasPrefix(f, row[0]+" "+row[1]+" ") && strings.Contains(f, " "+row[2]) {
					found = true
				}
			}
			if !found {
				t.Errorf("%s: no row for %v:\n%s", cmd, row, out)
			}
		}
	}
}
