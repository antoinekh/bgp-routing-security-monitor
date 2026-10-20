package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/nokia/bgp-routing-security-monitor/internal/buildinfo"
	"github.com/nokia/bgp-routing-security-monitor/internal/config"
	"github.com/nokia/bgp-routing-security-monitor/internal/server"
)

// ─── serve ───

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the RAVEN daemon (BMP receiver + RTR client + outputs)",
	RunE: func(cmd *cobra.Command, args []string) error {
		log := initLogger()
		log.Info("starting raven", "version", buildinfo.Version, "commit", buildinfo.Commit)

		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("config: %w", err)
		}

		// Pre-flight: bind each configured listen address briefly to fail
		// fast with one clear message instead of three mid-startup bind
		// errors from BMP, API, and Prometheus goroutines.
		ports := []string{cfg.BMP.Listen, server.APIListen(cfg)}
		if cfg.Outputs.Prometheus != nil {
			ports = append(ports, cfg.Outputs.Prometheus.Listen)
		}
		if err := preflightPortCheck(ports); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}

		demo, _ := cmd.Flags().GetBool("demo")

		srv, err := server.New(cfg, log)
		if err != nil {
			return err
		}
		srv.SetDemoMode(demo)
		return srv.Run()
	},
}

// preflightPortCheck attempts to bind each listen address briefly and
// releases it. Returns a single human-readable error naming the first
// port already in use; nil if all ports are free.
func preflightPortCheck(addrs []string) error {
	for _, addr := range addrs {
		if addr == "" {
			continue
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			display := addr
			if _, port, splitErr := net.SplitHostPort(addr); splitErr == nil && port != "" {
				display = port
			}
			return fmt.Errorf(
				"ERROR: port %s already in use — is another raven serve running?\n"+
					"   Run: pkill -f 'raven serve' && sleep 2",
				display)
		}
		_ = ln.Close()
	}
	return nil
}

// ─── version ───

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show RAVEN version and build information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("raven %s\n", buildinfo.Version)
		fmt.Printf("  commit: %s\n", buildinfo.Commit)
		fmt.Printf("  built:  %s\n", buildinfo.Date)
	},
}

// ─── status ───

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show BMP peer states, RTR cache health, and system status",
	RunE: func(cmd *cobra.Command, args []string) error {
		addr, _ := cmd.Flags().GetString("address")
		resp, err := apiGet(addr, "/api/v1/status", routerParam(cmd))
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		var status struct {
			Version string    `json:"version"`
			Uptime  string    `json:"uptime"`
			BMP     []peerRow `json:"bmp_peers"`
			RTR     struct {
				VRPCount uint64 `json:"vrp_count"`
				Serial   uint32 `json:"serial"`
			} `json:"rtr"`
			RouteTable struct {
				TotalRoutes uint64            `json:"total_routes"`
				ByPosture   map[string]uint64 `json:"by_posture"`
				ByRIB       map[string]uint64 `json:"by_rib"`
			} `json:"route_table"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
			return err
		}

		fmt.Printf("RAVEN %s  uptime %s\n\n", status.Version, status.Uptime)

		fmt.Printf("Route Table: %d routes received (Adj-RIB-In pre-policy)\n", status.RouteTable.TotalRoutes)
		for posture, count := range status.RouteTable.ByPosture {
			fmt.Printf("  %-20s %d\n", posture, count)
		}
		if len(status.RouteTable.ByRIB) > 1 {
			fmt.Printf("By RIB:\n")
			for _, rib := range []string{"adj-rib-in-pre", "adj-rib-in-post", "loc-rib", "adj-rib-out-pre", "adj-rib-out-post"} {
				if n, ok := status.RouteTable.ByRIB[rib]; ok {
					fmt.Printf("  %-20s %d\n", rib, n)
				}
			}
		}

		fmt.Printf("\nRPKI: %d VRPs (serial %d)\n", status.RTR.VRPCount, status.RTR.Serial)

		fmt.Printf("\nBMP Peers: %d\n", len(status.BMP))
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		out := anyOutbound(status.BMP)
		fmt.Fprintf(tw, "  ROUTER\tPEER\tASN\tSTATE\tROUTES%s\n", outHeader(out))
		for _, p := range status.BMP {
			fmt.Fprintf(tw, "  %s\t%s\t%d\t%s\t%d%s\n", p.router(), p.peer(), p.ASN, p.State, p.RouteCount, p.outCell(out))
		}
		tw.Flush()
		return nil
	},
}

// ─── peers ───

// peerRow is a BMP peer as /api/v1/status and /api/v1/peers report it: one
// peer on one router, in one instance, with its route count there.
type peerRow struct {
	Router            string            `json:"router"`
	RouterName        string            `json:"router_name"`
	PeerDistinguisher string            `json:"peer_distinguisher"`
	Addr              string            `json:"addr"`
	ASN               uint32            `json:"asn"`
	RouterID          string            `json:"router_id"`
	State             string            `json:"state"`
	RouteCount        uint64            `json:"route_count"` // Adj-RIB-In pre-policy
	RoutesByRIB       map[string]uint64 `json:"routes_by_rib"`
	UpSince           string            `json:"up_since"`
	MalformedInput    bool              `json:"malformed_input"`
	MalformedReason   string            `json:"malformed_reason"`
}

// anyMalformed reports whether any peer is marked for malformed input: only
// then does peers show a MALFORMED column, the RFC 7606 reason or "-".
func anyMalformed(rows []peerRow) bool {
	for _, p := range rows {
		if p.MalformedInput {
			return true
		}
	}
	return false
}

func malformedHeader(show bool) string {
	if show {
		return "\tMALFORMED"
	}
	return ""
}

func (p peerRow) malformedCell(show bool) string {
	switch {
	case !show:
		return ""
	case p.MalformedInput:
		return "\t" + p.MalformedReason
	}
	return "\t-"
}

// anyOutbound reports whether any peer has Adj-RIB-Out routes: only then do
// status and peers show an OUT column, the peer's Adj-RIB-Out pre-policy
// count, beside ROUTES (received) so the two are never added together.
func anyOutbound(rows []peerRow) bool {
	for _, p := range rows {
		if p.RoutesByRIB["adj-rib-out-pre"] != 0 {
			return true
		}
	}
	return false
}

func outHeader(show bool) string {
	if show {
		return "\tOUT"
	}
	return ""
}

func (p peerRow) outCell(show bool) string {
	if show {
		return fmt.Sprintf("\t%d", p.RoutesByRIB["adj-rib-out-pre"])
	}
	return ""
}

// router is the ROUTER column: the router's sysName, or its address.
func (p peerRow) router() string { return routerLabel(p.Router, p.RouterName) }

// peer is the PEER column: the address, with the VRF's RD for a peer that
// is not in the global instance.
func (p peerRow) peer() string {
	if p.PeerDistinguisher != "" {
		return p.Addr + " rd " + p.PeerDistinguisher
	}
	return p.Addr
}

func routerLabel(addr, name string) string {
	if name != "" {
		return name
	}
	return addr
}

// routerParam is the router query parameter from --router, or nil.
func routerParam(cmd *cobra.Command) url.Values {
	if v, _ := cmd.Flags().GetString("router"); v != "" {
		return url.Values{"router": {v}}
	}
	return nil
}

var peersCmd = &cobra.Command{
	Use:   "peers",
	Short: "List all BMP peers with session metadata",
	RunE: func(cmd *cobra.Command, args []string) error {
		addr, _ := cmd.Flags().GetString("address")
		resp, err := apiGet(addr, "/api/v1/peers", routerParam(cmd))
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		var peers []peerRow
		if err := json.NewDecoder(resp.Body).Decode(&peers); err != nil {
			return err
		}

		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		out := anyOutbound(peers)
		bad := anyMalformed(peers)
		fmt.Fprintf(tw, "ROUTER\tPEER\tASN\tROUTER ID\tSTATE\tROUTES%s\tUP SINCE%s\n", outHeader(out), malformedHeader(bad))
		for _, p := range peers {
			fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\t%d%s\t%s%s\n",
				p.router(), p.peer(), p.ASN, p.RouterID, p.State, p.RouteCount, p.outCell(out), p.UpSince,
				p.malformedCell(bad))
		}
		tw.Flush()
		return nil
	},
}

// ─── routes ───

var routesCmd = &cobra.Command{
	Use:   "routes",
	Short: "Query the route table (filterable by prefix, ASN, peer, posture)",
	RunE: func(cmd *cobra.Command, args []string) error {
		addr, _ := cmd.Flags().GetString("address")
		params := url.Values{}

		if v, _ := cmd.Flags().GetString("prefix"); v != "" {
			params.Set("prefix", v)
		}
		if v, _ := cmd.Flags().GetUint32("origin-asn"); v != 0 {
			params.Set("origin-asn", fmt.Sprintf("%d", v))
		}
		if v, _ := cmd.Flags().GetString("peer"); v != "" {
			params.Set("peer", v)
		}
		if v, _ := cmd.Flags().GetString("posture"); v != "" {
			params.Set("posture", v)
		}
		if v, _ := cmd.Flags().GetString("router"); v != "" {
			params.Set("router", v)
		}
		if v, _ := cmd.Flags().GetString("rib"); v != "" {
			params.Set("rib", v)
		}

		resp, err := apiGet(addr, "/api/v1/routes", params)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		format, _ := cmd.Flags().GetString("format")
		if format == "json" {
			io.Copy(os.Stdout, resp.Body)
			return nil
		}

		var routes []struct {
			Prefix     string   `json:"prefix"`
			Router     string   `json:"router"`
			RouterName string   `json:"router_name"`
			PeerAddr   string   `json:"peer"`
			PathID     uint32   `json:"path_id"`
			OriginASN  uint32   `json:"origin_asn"`
			ASPath     []uint32 `json:"as_path"`
			ROV        string   `json:"rov"`
			ASPA       string   `json:"aspa"`
			Posture    string   `json:"posture"`

			ASPAProcedure       string `json:"aspa_procedure"`
			ASPAProcedureSource string `json:"aspa_procedure_source"`
			ASPAFailingHop      *struct {
				CustomerASN uint32 `json:"customer_asn"`
				ProviderASN uint32 `json:"provider_asn"`
			} `json:"aspa_failing_hop"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&routes); err != nil {
			return err
		}
		wide := format == "wide"

		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		prefixes := make([]string, len(routes))
		for i, r := range routes {
			prefixes[i] = r.Prefix
		}
		pw := prefixColWidth(prefixes)
		fmt.Fprintf(tw, "%-*s\tROUTER\tPEER\tORIGIN\tROV\tASPA\tPOSTURE", pw, "PREFIX")
		if wide {
			fmt.Fprint(tw, "\tASPA PROCEDURE\tPROCEDURE SOURCE\tFAILING HOP")
		}
		fmt.Fprintln(tw)
		for _, r := range routes {
			asPathStr := formatASPath(r.ASPath)
			origin := fmt.Sprintf("AS%d", r.OriginASN)
			if r.OriginASN == 0 {
				origin = "-"
			}
			peer := r.PeerAddr
			if r.PathID != 0 {
				peer = fmt.Sprintf("%s path %d", peer, r.PathID)
			}
			fmt.Fprintf(tw, "%-*s\t%s\t%s\t%s\t%s\t%s\t%s",
				pw, r.Prefix, routerLabel(r.Router, r.RouterName), peer, origin, r.ROV, r.ASPA, r.Posture)
			if wide {
				hop := "-"
				if h := r.ASPAFailingHop; h != nil {
					hop = fmt.Sprintf("%d->%d", h.CustomerASN, h.ProviderASN)
				}
				fmt.Fprintf(tw, "\t%s\t%s\t%s", r.ASPAProcedure, r.ASPAProcedureSource, hop)
			}
			fmt.Fprintln(tw)
			_ = asPathStr
		}
		tw.Flush()
		return nil
	},
}

// prefixColWidth returns the column width to use for a PREFIX column: the
// longest prefix string in the result set, but never less than 24 characters
// so the column reads cleanly with IPv6 entries like 2001:db8:2121::/48.
func prefixColWidth(prefixes []string) int {
	w := 24
	for _, p := range prefixes {
		if l := len(p); l > w {
			w = l
		}
	}
	return w
}

// ─── validate ───

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "One-shot validation of a prefix against current RPKI state",
	RunE: func(cmd *cobra.Command, args []string) error {
		addr, _ := cmd.Flags().GetString("address")
		prefix, _ := cmd.Flags().GetString("prefix")

		// One-shot validation against an RTR cache does not exist yet;
		// these flags were accepted and silently ignored.
		for _, name := range []string{"origin-asn", "rtr"} {
			if cmd.Flags().Changed(name) {
				return fmt.Errorf("--%s is not supported yet; validate reads the running daemon's routes for --prefix", name)
			}
		}
		if prefix == "" {
			return fmt.Errorf("--prefix is required")
		}

		params := url.Values{"prefix": {prefix}}
		resp, err := apiGet(addr, "/api/v1/routes", params)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		var routes []struct {
			Prefix    string `json:"prefix"`
			PeerAddr  string `json:"peer"`
			OriginASN uint32 `json:"origin_asn"`
			ROV       string `json:"rov"`
			ROVReason string `json:"rov_reason"`
			Posture   string `json:"posture"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&routes); err != nil {
			return err
		}

		if len(routes) == 0 {
			fmt.Println("no routes found for prefix", prefix)
			return nil
		}

		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		prefixes := make([]string, len(routes))
		for i, r := range routes {
			prefixes[i] = r.Prefix
		}
		pw := prefixColWidth(prefixes)
		fmt.Fprintf(tw, "%-*s\tPEER\tORIGIN\tROV\tPOSTURE\tREASON\n", pw, "PREFIX")
		for _, r := range routes {
			origin := fmt.Sprintf("AS%d", r.OriginASN)
			if r.OriginASN == 0 {
				origin = "-"
			}
			fmt.Fprintf(tw, "%-*s\t%s\t%s\t%s\t%s\t%s\n",
				pw, r.Prefix, r.PeerAddr, origin, r.ROV, r.Posture, r.ROVReason)
		}
		tw.Flush()
		return nil
	},
}

// ─── watch ───

var watchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Stream live validation state changes",
	RunE: func(cmd *cobra.Command, args []string) error {
		addr, _ := cmd.Flags().GetString("address")
		params := url.Values{}
		// Each filter used to be read here but posture was the only one sent.
		if v, _ := cmd.Flags().GetString("prefix"); v != "" {
			params.Set("prefix", v)
		}
		if v, _ := cmd.Flags().GetUint32("origin-asn"); v != 0 {
			params.Set("origin-asn", fmt.Sprintf("%d", v))
		}
		if v, _ := cmd.Flags().GetString("peer"); v != "" {
			params.Set("peer", v)
		}
		if v, _ := cmd.Flags().GetString("posture"); v != "" {
			params.Set("posture", v)
		}
		if v, _ := cmd.Flags().GetString("router"); v != "" {
			params.Set("router", v)
		}

		u := fmt.Sprintf("http://%s/api/v1/watch", addr)
		if len(params) > 0 {
			u += "?" + params.Encode()
		}

		resp, err := http.Get(u)
		if err != nil {
			return fmt.Errorf("connect to daemon: %w\n  is 'raven serve' running?", err)
		}
		defer resp.Body.Close()

		fmt.Println("watching for route events... (Ctrl+C to stop)")
		fmt.Println()

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if !strings.HasPrefix(line, "data: ") {
				continue
			}
			data := line[6:]

			var r watchRoute
			if err := json.Unmarshal([]byte(data), &r); err != nil {
				continue
			}
			fmt.Println(r.line())
		}
		return scanner.Err()
	},
}

// watchRoute is the part of a watch event's route that raven watch shows.
type watchRoute struct {
	Prefix         string   `json:"prefix"`
	PeerAddr       string   `json:"peer"`
	OriginASN      uint32   `json:"origin_asn"`
	ASPath         []uint32 `json:"as_path"`
	ROV            string   `json:"rov"`
	ASPA           string   `json:"aspa"`
	ASPAFailingHop *struct {
		CustomerASN uint32 `json:"customer_asn"`
		ProviderASN uint32 `json:"provider_asn"`
	} `json:"aspa_failing_hop"`
	Posture string `json:"posture"`
}

// line is r as one raven watch line. An ASPA Invalid shows its failing hop
// as hop(C→P): C's ASPA does not list P.
func (r watchRoute) line() string {
	origin := fmt.Sprintf("AS%d", r.OriginASN)
	if r.OriginASN == 0 {
		origin = "-"
	}
	aspa := "ASPA:" + r.ASPA
	if h := r.ASPAFailingHop; h != nil {
		aspa += fmt.Sprintf(" hop(%d→%d)", h.CustomerASN, h.ProviderASN)
	}
	return fmt.Sprintf("[%s] %s via %s origin:%s AS_PATH:%v rov:%s %s posture:%s",
		r.Posture, r.Prefix, r.PeerAddr, origin, r.ASPath, r.ROV, aspa, r.Posture)
}

// ─── helpers ───

func apiGet(addr string, path string, params url.Values) (*http.Response, error) {
	u := fmt.Sprintf("http://%s%s", addr, path)
	if len(params) > 0 {
		u += "?" + params.Encode()
	}
	resp, err := http.Get(u) //nolint:noctx
	if err != nil {
		return nil, fmt.Errorf("connect to daemon at %s: %w\n  is 'raven serve' running?", addr, err)
	}
	return resp, nil
}

func apiPost(addr string, path string) (*http.Response, error) {
	u := fmt.Sprintf("http://%s%s", addr, path)
	resp, err := http.Post(u, "application/json", http.NoBody) //nolint:noctx
	if err != nil {
		return nil, fmt.Errorf("connect to daemon at %s: %w\n  is 'raven serve' running?", addr, err)
	}
	return resp, nil
}

func formatASPath(path []uint32) string {
	if len(path) == 0 {
		return "-"
	}
	parts := make([]string, len(path))
	for i, asn := range path {
		parts[i] = fmt.Sprintf("%d", asn)
	}
	return strings.Join(parts, " ")
}

func init() {
	// serve flags
	serveCmd.Flags().Bool("demo", false, "use test VRPs instead of live RTR connection")

	// status and peers flags: --router limits the peers listed. Status
	// totals stay daemon-wide.
	statusCmd.Flags().String("router", "", "show only this monitored router's peers: its address or BMP sysName")
	peersCmd.Flags().String("router", "", "show only this monitored router's peers: its address or BMP sysName")

	// routes flags
	routesCmd.Flags().String("prefix", "", "filter by prefix (e.g. 1.0.0.0/24)")
	routesCmd.Flags().Uint32("origin-asn", 0, "filter by origin ASN")
	routesCmd.Flags().String("peer", "", "filter by BMP peer address")
	routesCmd.Flags().String("posture", "", "filter by security posture")
	routesCmd.Flags().String("router", "", "filter by monitored router: its address or BMP sysName")
	routesCmd.Flags().String("rib", "adj-rib-in-pre",
		"RIB to list: adj-rib-in-pre, adj-rib-in-post, adj-rib-out-pre, adj-rib-out-post or loc-rib")
	routesCmd.Flags().String("format", "table", "output format: table, wide, json")

	// validate flags
	validateCmd.Flags().String("prefix", "", "prefix to validate (required)")
	validateCmd.Flags().Uint32("origin-asn", 0, "origin ASN to validate (not supported yet)")
	validateCmd.Flags().String("rtr", "", "RTR cache address for one-shot mode (not supported yet)")

	// watch flags
	watchCmd.Flags().String("prefix", "", "filter by prefix")
	watchCmd.Flags().Uint32("origin-asn", 0, "filter by origin ASN")
	watchCmd.Flags().String("peer", "", "filter by peer")
	watchCmd.Flags().String("posture", "", "filter by posture")
	watchCmd.Flags().String("router", "", "filter by monitored router: its address or BMP sysName")
}
