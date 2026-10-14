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
