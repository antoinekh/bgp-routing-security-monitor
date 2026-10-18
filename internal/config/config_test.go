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
