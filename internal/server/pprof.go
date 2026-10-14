package server

import (
	"context"
	"fmt"
	"html"
	"net"
	"net/http"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The pprof endpoint deliberately does not import net/http/pprof. That
// package registers its handlers on http.DefaultServeMux in init(), so merely
// linking it would expose profiling on any server that falls back to the
// default mux, whether or not debug.pprof is enabled. The handlers below serve
// the same paths and formats straight from runtime/pprof, on a mux of their
// own, so `go tool pprof` works against them unchanged.

const (
	// pprofReadHeaderTimeout bounds slow clients. There is no write timeout:
	// a CPU profile or trace legitimately holds the response open for as
	// many seconds as the caller asks for.
	pprofReadHeaderTimeout = 10 * time.Second

	pprofDefaultCPUSeconds   = 30
	pprofDefaultTraceSeconds = 1
)

// startPprof opens the debug.pprof listener and serves runtime profiles on it
// until ctx is cancelled, registering the server goroutine on wg. It returns
// the bound address, or nil when pprof is disabled or the listener could not
// be opened. A listen failure is logged rather than returned: a diagnostics
// endpoint must never keep the daemon from running.
func (s *Server) startPprof(ctx context.Context, wg *sync.WaitGroup) net.Addr {
	addr := s.cfg.Debug.Pprof.Listen
	if addr == "" {
		return nil
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		s.log.Error("failed to start pprof endpoint", "addr", addr, "error", err)
		return nil
	}
	bound := ln.Addr()

	// Judge exposure by the address actually bound, not the configured
	// string, so hostnames and empty hosts (":6060" binds every interface)
	// are classified by what they resolved to.
	if !isLoopbackAddr(bound) {
		s.log.Warn("pprof endpoint is exposed beyond localhost; it is unauthenticated and profiles reveal process memory contents",
			"addr", bound.String())
	}

	srv := &http.Server{Handler: newPprofMux(), ReadHeaderTimeout: pprofReadHeaderTimeout}

	wg.Add(1)
	go func() {
		defer wg.Done()
		go func() {
			<-ctx.Done()
			srv.Close()
		}()
		if err := srv.Serve(ln); err != http.ErrServerClosed {
			s.log.Error("pprof server error", "error", err)
		}
	}()

	s.log.Info("pprof endpoint started", "addr", bound.String(), "path", "/debug/pprof/")
	return bound
}

// isLoopbackAddr reports whether a is a TCP address on a loopback interface
// (127.0.0.0/8 or ::1). The unspecified address (0.0.0.0, ::) is not.
func isLoopbackAddr(a net.Addr) bool {
	tcp, ok := a.(*net.TCPAddr)
	return ok && tcp.IP.IsLoopback()
}

// newPprofMux returns a fresh mux serving the /debug/pprof/ endpoints.
func newPprofMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprofIndex)
	mux.HandleFunc("/debug/pprof/profile", pprofCPUProfile)
	mux.HandleFunc("/debug/pprof/trace", pprofTrace)
	return mux
}

// pprofIndex serves a named runtime profile (heap, allocs, goroutine, block,
// mutex, threadcreate) at /debug/pprof/<name>, and an index of them at
// /debug/pprof/.
func pprofIndex(w http.ResponseWriter, r *http.Request) {
	if name := strings.TrimPrefix(r.URL.Path, "/debug/pprof/"); name != "" {
		pprofNamed(w, r, name)
		return
	}

	profiles := pprof.Profiles()
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].Name() < profiles[j].Name() })

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintln(w, "<html><head><title>RAVEN /debug/pprof/</title></head><body><h1>/debug/pprof/</h1><ul>")
	for _, p := range profiles {
		name := html.EscapeString(p.Name())
		fmt.Fprintf(w, "<li><a href=\"%s?debug=1\">%s</a> (%d)</li>\n", name, name, p.Count())
	}
	fmt.Fprintf(w, "<li><a href=\"profile\">profile</a> (CPU, %ds by default)</li>\n", pprofDefaultCPUSeconds)
	fmt.Fprintf(w, "<li><a href=\"trace\">trace</a> (execution trace, %ds by default)</li>\n", pprofDefaultTraceSeconds)
	fmt.Fprintln(w, "</ul></body></html>")
}

// pprofNamed writes one runtime/pprof profile. debug=0 (the default) is the
// gzipped protobuf format go tool pprof reads; debug=1 and 2 are text.
// gc=1 on the heap profile runs a GC first so the in-use figures are current.
func pprofNamed(w http.ResponseWriter, r *http.Request, name string) {
	p := pprof.Lookup(name)
	if p == nil {
		pprofError(w, http.StatusNotFound, "unknown profile "+strconv.Quote(name))
		return
	}
	if r.FormValue("seconds") != "" {
		// net/http/pprof computes a delta here; take two snapshots and
		// compare them with `go tool pprof -base` instead.
		pprofError(w, http.StatusBadRequest, "seconds= delta profiles are not supported; diff two snapshots with go tool pprof -base")
		return
	}
	debug, _ := strconv.Atoi(r.FormValue("debug"))
	if name == "heap" && r.FormValue("gc") != "" {
		runtime.GC()
	}

	w.Header().Set("X-Content-Type-Options", "nosniff")
	if debug != 0 {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	}
	// A write error here means the client went away mid-profile; there is
	// nobody left to report it to.
	_ = p.WriteTo(w, debug)
}

// pprofCPUProfile serves a CPU profile covering the next seconds= seconds.
func pprofCPUProfile(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="profile"`)
	if err := pprof.StartCPUProfile(w); err != nil {
		pprofError(w, http.StatusInternalServerError, "could not enable CPU profiling: "+err.Error())
		return
	}
	// Send the 200 now: the profile itself only arrives at the end, and this
	// tells the caller that profiling is actually running.
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	pprofSleep(r, pprofSeconds(r, pprofDefaultCPUSeconds))
	pprof.StopCPUProfile()
}

// pprofTrace serves an execution trace covering the next seconds= seconds.
func pprofTrace(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="trace"`)
	if err := trace.Start(w); err != nil {
		pprofError(w, http.StatusInternalServerError, "could not enable tracing: "+err.Error())
		return
	}
	pprofSleep(r, pprofSeconds(r, pprofDefaultTraceSeconds))
	trace.Stop()
}

// pprofSeconds parses the seconds= query parameter, falling back to def for
// a missing, malformed or non-positive value.
func pprofSeconds(r *http.Request, def float64) time.Duration {
	sec, err := strconv.ParseFloat(r.FormValue("seconds"), 64)
	if err != nil || sec <= 0 {
		sec = def
	}
	return time.Duration(sec * float64(time.Second))
}

// pprofSleep waits for d, or until the request is abandoned. The server
// closing at shutdown cancels the request context too, so a long CPU profile
// ends with the daemon instead of leaving profiling switched on.
func pprofSleep(r *http.Request, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-r.Context().Done():
	}
}

// pprofError replaces the profile download headers with a plain-text error.
func pprofError(w http.ResponseWriter, status int, msg string) {
	w.Header().Del("Content-Disposition")
	http.Error(w, msg, status)
}
