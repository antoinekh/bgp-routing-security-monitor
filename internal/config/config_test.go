package config

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func loadYAML(t *testing.T, yaml string) *Config {
	t.Helper()
	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.SetConfigType("yaml")
	if err := viper.ReadConfig(strings.NewReader(yaml)); err != nil {
		t.Fatalf("reading config: %v", err)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

func TestPprofDisabledByDefault(t *testing.T) {
	for name, yaml := range map[string]string{
		"section absent":      "bmp:\n  listen: \":11019\"\n",
		"debug without pprof": "debug: {}\n",
		"listen empty":        "debug:\n  pprof:\n    listen: \"\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			if got := loadYAML(t, yaml).Debug.Pprof.Listen; got != "" {
				t.Fatalf("debug.pprof.listen = %q, want empty (disabled)", got)
			}
		})
	}
}

func TestPprofListenFromYAML(t *testing.T) {
	cfg := loadYAML(t, "debug:\n  pprof:\n    listen: \"localhost:6060\"\n")
	if got := cfg.Debug.Pprof.Listen; got != "localhost:6060" {
		t.Fatalf("debug.pprof.listen = %q, want %q", got, "localhost:6060")
	}
}

func TestASPAPeersValidation(t *testing.T) {
	tests := []struct {
		name    string
		peers   string
		wantErr string // empty: valid
	}{
		{"absent", "", ""},
		{"empty list", "  aspa-peers: []\n", ""},
		{"valid", `  aspa-peers:
    - {address: 192.0.2.1, neighbor-role: provider}
    - {address: "2001:db8::1", neighbor-role: rs}
    - {asn: 64500, neighbor-role: customer}
    - {asn: 64501, neighbor-role: peer}
    - {asn: 64502, neighbor-role: rs-client}
`, ""},
		{"address and asn", "  aspa-peers:\n    - {address: 192.0.2.1, asn: 64500, neighbor-role: peer}\n", "exactly one of address or asn"},
		{"neither", "  aspa-peers:\n    - {neighbor-role: peer}\n", "exactly one of address or asn"},
		{"bad role", "  aspa-peers:\n    - {asn: 64500, neighbor-role: transit}\n", `invalid neighbor-role "transit"`},
		{"missing role", "  aspa-peers:\n    - {asn: 64500}\n", `invalid neighbor-role ""`},
		{"bad address", "  aspa-peers:\n    - {address: not-an-ip, neighbor-role: peer}\n", "invalid address"},
		{"duplicate asn", "  aspa-peers:\n    - {asn: 64500, neighbor-role: peer}\n    - {asn: 64500, neighbor-role: provider}\n", "duplicate asn 64500"},
		{"duplicate address", "  aspa-peers:\n    - {address: 192.0.2.1, neighbor-role: peer}\n    - {address: 192.0.2.1, neighbor-role: provider}\n", "duplicate address 192.0.2.1"},
		{"duplicate mapped address", "  aspa-peers:\n    - {address: 192.0.2.1, neighbor-role: peer}\n    - {address: \"::ffff:192.0.2.1\", neighbor-role: provider}\n", "duplicate address 192.0.2.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viper.Reset()
			t.Cleanup(viper.Reset)
			viper.SetConfigType("yaml")
			if err := viper.ReadConfig(strings.NewReader("validation:\n  aspa: true\n" + tt.peers)); err != nil {
				t.Fatalf("reading config: %v", err)
			}
			_, err := Load()
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("Load: %v", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Fatalf("Load error = %v, want one containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestAllowedRoutersValidation(t *testing.T) {
	load := func(yaml string) (*Config, error) {
		viper.Reset()
		t.Cleanup(viper.Reset)
		viper.SetConfigType("yaml")
		if err := viper.ReadConfig(strings.NewReader(yaml)); err != nil {
			t.Fatalf("reading config: %v", err)
		}
		return Load()
	}
	cfg, err := load("bmp:\n  allowed-routers: [192.0.2.10, 10.0.0.0/8, \"2001:db8::/32\", \"::ffff:198.51.100.1\", 203.0.113.7/24]\n")
	if err != nil {
		t.Fatalf("valid list rejected: %v", err)
	}
	got, err := ParseAllowedRouters(cfg.BMP.AllowedRouters)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.10/32", "10.0.0.0/8", "2001:db8::/32", "198.51.100.1/32", "203.0.113.0/24"}
	for i, p := range got {
		if p.String() != want[i] {
			t.Errorf("entry %d parsed as %s, want %s", i, p, want[i])
		}
	}
	for _, bad := range []string{"router1", "10.0.0.0/33", "192.0.2.300", "fe80::1%eth0", "::ffff:0.0.0.0/80", "10.0.0.0/"} {
		_, err := load("bmp:\n  allowed-routers: [\"" + bad + "\"]\n")
		if err == nil || !strings.Contains(err.Error(), "bmp.allowed-routers[0]") {
			t.Errorf("%q: error = %v, want a bmp.allowed-routers[0] error", bad, err)
		}
	}
	if cfg, err := load("bmp:\n  listen: \":11019\"\n"); err != nil || len(cfg.BMP.AllowedRouters) != 0 {
		t.Errorf("absent list: cfg %v, err %v; want empty and valid", cfg.BMP.AllowedRouters, err)
	}
}

func TestAPIListenDefault(t *testing.T) {
	if got := loadYAML(t, "bmp:\n  listen: \":11019\"\n").API.Listen; got != "127.0.0.1:11020" {
		t.Errorf("default api.listen = %q, want 127.0.0.1:11020", got)
	}
	if got := loadYAML(t, "api:\n  listen: \"0.0.0.0:11020\"\n").API.Listen; got != "0.0.0.0:11020" {
		t.Errorf("explicit api.listen = %q, want 0.0.0.0:11020", got)
	}
}
