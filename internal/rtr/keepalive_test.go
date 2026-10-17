package rtr

import (
	"testing"
	"time"
)

// RTR connections are dialed with TCP keepalive on (60s idle, then 4 probes
// 15s apart), so a dead cache is found in about two minutes even when no
// query is outstanding. The TLS transport dials its TCP connection with the
// same dialer. (keepalive_linux_test.go checks the options on live sockets.)
func TestRTRDialerEnablesKeepAlive(t *testing.T) {
	c := &Client{}
	got := c.dialer().KeepAliveConfig
	if !got.Enable || got.Idle != 60*time.Second || got.Interval != 15*time.Second || got.Count != 4 {
		t.Errorf("dialer KeepAliveConfig = %+v, want enabled, idle 60s, interval 15s, count 4", got)
	}
}
