package config

import (
	"os"
	"path/filepath"
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

// loadWithEnv runs the same sequence the CLI does — read the config file,
// wire up env overrides, Load — on a fresh viper, and returns the result.
// An empty body means no config file at all.
func loadWithEnv(t *testing.T, body string) *Config {
	t.Helper()
	viper.Reset()
	t.Cleanup(viper.Reset)

	if body != "" {
		path := filepath.Join(t.TempDir(), "raven.yaml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}
		viper.SetConfigFile(path)
		if err := viper.ReadInConfig(); err != nil {
			t.Fatalf("read config: %v", err)
		}
	}

	ConfigureEnv()
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

// ─── TestEnvOverridesNestedKeys ───

// RAVEN_BMP_LISTEN must beat bmp.listen from the file. Before the key
// replacer, viper looked the key up as RAVEN_BMP.LISTEN and the file value
// silently won.
func TestEnvOverridesNestedKeys(t *testing.T) {
	t.Setenv("RAVEN_BMP_LISTEN", "127.0.0.1:21119")
	t.Setenv("RAVEN_API_LISTEN", "127.0.0.1:21120")
	t.Setenv("RAVEN_LOGGING_LEVEL", "debug")

	cfg := loadWithEnv(t, "bmp:\n  listen: 127.0.0.1:21019\nlogging:\n  level: info\n")

	if cfg.BMP.Listen != "127.0.0.1:21119" {
		t.Errorf("BMP.Listen = %q, want the RAVEN_BMP_LISTEN value 127.0.0.1:21119", cfg.BMP.Listen)
	}
	if cfg.API.Listen != "127.0.0.1:21120" {
		t.Errorf("API.Listen = %q, want the RAVEN_API_LISTEN value 127.0.0.1:21120 over the default", cfg.API.Listen)
	}
	if cfg.Logging.Level != "debug" {
		t.Errorf("Logging.Level = %q, want the RAVEN_LOGGING_LEVEL value debug", cfg.Logging.Level)
	}
}

// ─── TestEnvOverridesHyphenatedKeys ───

// A hyphen in a key maps to an underscore, like the nesting dot.
func TestEnvOverridesHyphenatedKeys(t *testing.T) {
	t.Setenv("RAVEN_VALIDATION_ASPA_DEFAULT_PROCEDURE", "downstream")
	t.Setenv("RAVEN_EXTERNAL_RIPESTAT_RATE_LIMIT_PER_MIN", "3")

	cfg := loadWithEnv(t, "")

	if cfg.Validation.ASPADefaultProcedure != "downstream" {
		t.Errorf("Validation.ASPADefaultProcedure = %q, want downstream", cfg.Validation.ASPADefaultProcedure)
	}
	if cfg.External.RIPEstat.RateLimitPerMin != 3 {
		t.Errorf("External.RIPEstat.RateLimitPerMin = %d, want 3", cfg.External.RIPEstat.RateLimitPerMin)
	}
}

// ─── TestEnvOverridesKeysWithoutDefaults ───

// viper.Unmarshal only fills keys viper knows about. A key with no SetDefault
// and no entry in the file — including one under a pointer section like
// bmp.tls — must still be settable from the environment.
func TestEnvOverridesKeysWithoutDefaults(t *testing.T) {
	t.Setenv("RAVEN_RTR_EXPIRE_INTERVAL", "600")
	t.Setenv("RAVEN_BMP_TLS_CA", "/etc/raven/ca.pem")
	t.Setenv("RAVEN_BMP_TLS_TLS_MIN_VERSION", "1.3")

	cfg := loadWithEnv(t, "")

	if cfg.RTR.ExpireInterval != 600 {
		t.Errorf("RTR.ExpireInterval = %d, want 600", cfg.RTR.ExpireInterval)
	}
	if cfg.BMP.TLS == nil {
		t.Fatal("BMP.TLS = nil, want it built from RAVEN_BMP_TLS_*")
	}
	if cfg.BMP.TLS.CA != "/etc/raven/ca.pem" {
		t.Errorf("BMP.TLS.CA = %q, want /etc/raven/ca.pem", cfg.BMP.TLS.CA)
	}
	if cfg.BMP.TLS.MinVersion != "1.3" {
		t.Errorf("BMP.TLS.MinVersion = %q, want 1.3", cfg.BMP.TLS.MinVersion)
	}
}

// ─── TestUnsetEnvLeavesOptionalSectionsNil ───

// Binding every key must not conjure up optional sections: with no env var
// and no file entry, BMP TLS and Kafka ingest stay nil (plain TCP, embedded
// receiver), as before.
func TestUnsetEnvLeavesOptionalSectionsNil(t *testing.T) {
	cfg := loadWithEnv(t, "")

	if cfg.BMP.TLS != nil {
		t.Errorf("BMP.TLS = %+v, want nil", cfg.BMP.TLS)
	}
	if cfg.BMP.Kafka != nil {
		t.Errorf("BMP.Kafka = %+v, want nil", cfg.BMP.Kafka)
	}
	if cfg.Outputs.Kafka != nil {
		t.Errorf("Outputs.Kafka = %+v, want nil", cfg.Outputs.Kafka)
	}
	if cfg.BMP.Listen != ":11019" {
		t.Errorf("BMP.Listen = %q, want the default :11019", cfg.BMP.Listen)
	}
}
