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
		"--peer", "80.81.194.180", "--posture", "secured")
	want := url.Values{"prefix": {"1.1.1.0/24"}, "origin-asn": {"13335"}, "peer": {"80.81.194.180"}, "posture": {"secured"}}
	if got.Encode() != want.Encode() {
		t.Errorf("watch query = %q, want %q", got.Encode(), want.Encode())
	}
	runCLI(t, srv, "watch", "--prefix", "", "--origin-asn", "0", "--peer", "", "--posture", "")
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
	out := runCLI(t, srv, "routes", "--prefix", "1.1.1.0/24", "--peer", "80.81.194.180", "--format", "wide")
	if got.Get("prefix") != "1.1.1.0/24" || got.Get("peer") != "80.81.194.180" {
		t.Errorf("routes query = %q, want prefix and peer", got.Encode())
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 || !strings.HasSuffix(strings.TrimSpace(lines[0]), "FAILING HOP") ||
		!strings.HasSuffix(strings.TrimSpace(lines[1]), "1199->65000") || !strings.HasSuffix(strings.TrimSpace(lines[2]), "-") {
		t.Errorf("wide output:\n%s", out)
	}
	runCLI(t, srv, "routes", "--prefix", "", "--peer", "", "--format", "table")
}
