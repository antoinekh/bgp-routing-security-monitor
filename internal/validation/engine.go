package validation

import (
	"slices"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/nokia/bgp-routing-security-monitor/internal/metrics"
	"github.com/nokia/bgp-routing-security-monitor/internal/routetable"
	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
	"github.com/nokia/bgp-routing-security-monitor/internal/validation/aspa"
	"github.com/nokia/bgp-routing-security-monitor/internal/validation/rov"
	"log/slog"
)

// Engine annotates routes with ROV (and later ASPA) validation results.
type Engine struct {
	rovAnnotator  *rov.Annotator
	aspaAnnotator *aspa.Annotator
	aspaSelector  *aspa.Selector
	vrpStore      *store.VRPStore
	table         *routetable.Table
	log           *slog.Logger

	// aspaCount holds raven_aspa_validations_total's series, indexed by
	// procedure, source and state, resolved once so counting allocates nothing.
	aspaCount [2][3][4]prometheus.Counter
}

// NewEngine creates a validation engine. sel picks each route's ASPA
// procedure; nil selects upstream for every route.
func NewEngine(vrpStore *store.VRPStore, aspaStore *store.ASPAStore, sel *aspa.Selector, table *routetable.Table, log *slog.Logger) *Engine {
	e := &Engine{
		rovAnnotator:  rov.NewAnnotator(vrpStore),
		aspaAnnotator: aspa.NewAnnotator(aspaStore),
		aspaSelector:  sel,
		vrpStore:      vrpStore,
		table:         table,
		log:           log.With("subsystem", "validation"),
	}
	for p := range e.aspaCount {
		for src := range e.aspaCount[p] {
			for st := range e.aspaCount[p][src] {
				e.aspaCount[p][src][st] = metrics.ASPAValidationsTotal.WithLabelValues(
					types.ASPAProcedure(p).String(),
					types.ASPAProcedureSource(src).String(),
					types.ASPAState(st).String())
			}
		}
	}
	return e
}

// ValidateRoute performs ROV and ASPA on a single route and updates its
// annotations. Called by the ingest pipeline for each new route; revalidation
// runs the same annotate, so both pick the ASPA procedure the same way.
func (e *Engine) ValidateRoute(route *types.Route) {
	route.ROV, route.ASPA, route.SecurityPosture = e.annotate(route)
}

// aspaNotVerifiedOutbound is the ASPA Reason on Adj-RIB-Out routes.
const aspaNotVerifiedOutbound = "not ASPA-verified: Adj-RIB-Out (outbound) route; ASPA verification applies to routes received from a neighbor"

// annotate runs ROV and ASPA for route against the current stores without
// changing it.
func (e *Engine) annotate(route *types.Route) (types.ROVResult, types.ASPAResult, types.SecurityPosture) {
	// ROV
	rovRes := e.rovAnnotator.Validate(route)
	if route.RIBType.IsAdjRIBOut() {
		// An Adj-RIB-Out route is one the router sends, not one it
		// received. ASPA verification (upstream or downstream) is defined
		// for a route received from a neighbour, by the neighbour's
		// relationship to the verifier, so it says nothing meaningful
		// here. ROV, about the prefix's origin, still applies.
		a := types.ASPAResult{State: types.ASPAUnverifiable, Reason: aspaNotVerifiedOutbound}
		return rovRes, a, types.ComputePosture(rovRes.State, a.State)
	}
	// ASPA, with the procedure for the peer the route was learned from
	sel := e.aspaSelector.Select(route.PeerAddr, route.PeerASN)
	a := e.aspaAnnotator.ValidateSelection(route, sel)
	if int(a.Procedure) < 2 && int(a.ProcedureSource) < 3 && int(a.State) < 4 {
		e.aspaCount[a.Procedure][a.ProcedureSource][a.State].Inc()
	}
	// Combined posture
	return rovRes, a, types.ComputePosture(rovRes.State, a.State)
}

// Revalidated re-runs validation on route against the current VRP and ASPA
// stores and reports whether any annotation changed; if so, it returns an
// updated copy. route itself is not modified: routes in the table are read
// concurrently and must never change in place. A route whose results did not
// change is not copied.
func (e *Engine) Revalidated(route *types.Route) (types.Route, bool) {
	var ann types.Route
	ann.ROV, ann.ASPA, ann.SecurityPosture = e.annotate(route)
	if sameValidation(route, &ann) {
		return types.Route{}, false
	}
	cp := *route
	cp.ROV, cp.ASPA, cp.SecurityPosture = ann.ROV, ann.ASPA, ann.SecurityPosture
	return cp, true
}

// sameValidation reports whether a and b carry the same validation results.
func sameValidation(a, b *types.Route) bool {
	if a.SecurityPosture != b.SecurityPosture ||
		a.ROV.State != b.ROV.State || a.ROV.Reason != b.ROV.Reason ||
		!slices.Equal(a.ROV.MatchedVRPs, b.ROV.MatchedVRPs) ||
		a.ASPA.State != b.ASPA.State || a.ASPA.Procedure != b.ASPA.Procedure ||
		a.ASPA.ProcedureSource != b.ASPA.ProcedureSource || a.ASPA.Reason != b.ASPA.Reason ||
		!slices.Equal(a.ASPA.HopDetails, b.ASPA.HopDetails) {
		return false
	}
	fa, fb := a.ASPA.FailingHop, b.ASPA.FailingHop
	return (fa == nil) == (fb == nil) && (fa == nil || *fa == *fb)
}

// Revalidation is one pass re-running validation after the VRP or ASPA store
// changed. It is applied a chunk at a time by the Route Table's single writer
// (the ingest loop), between ingest events.
//
// A full pass revalidates every route in the table. An incremental pass
// revalidates only the routes an RTR delta can affect (ARCHITECTURE.md §2.2):
// for each changed VRP prefix, the routes at or more specific than it, found
// through the prefix index; and, if any ASPA record changed, the routes whose
// AS_PATH holds one of the changed customer ASNs, found by a scan that reads
// routes in place and keeps only those that match.
//
// A route whose results changed is replaced by a revalidated copy, and only
// if the table still holds that route; one withdrawn or re-announced since
// the pass read it is skipped, since a re-announcement was validated on
// ingest against the current stores. Routes added after the delta's store
// changes were likewise validated against the changed stores, so a pass that
// does not see them misses nothing.
type Revalidation struct {
	e    *Engine
	Full bool

	// Full pass.
	scan *routetable.Scan

	// Incremental pass: the routes under the changed VRP prefixes first,
	// then the ASPA scan's matches that were not among them.
	vrpKeys  []types.RouteKey
	vrpSet   map[types.RouteKey]struct{}
	aspaScan *routetable.MatchScan
	pending  []*types.Route

	Candidates int // routes the delta selected (a full pass: every route checked)
	Checked    int // routes revalidated
	Changed    int // routes replaced with new results
	Skipped    int // routes with new results gone or replaced before they could be applied

	ASPAScanned  int           // routes the ASPA scan examined
	ASPAScanTime time.Duration // time spent in the ASPA scan
}

// NewRevalidation starts a full revalidation pass over the table.
func (e *Engine) NewRevalidation() *Revalidation {
	return &Revalidation{e: e, Full: true, scan: e.table.NewScan()}
}

// NewDeltaRevalidation starts a pass revalidating the routes d can affect, or
// a full pass if d is Full or nil.
func (e *Engine) NewDeltaRevalidation(d *store.Delta) *Revalidation {
	if d == nil || d.Full {
		return e.NewRevalidation()
	}
	rv := &Revalidation{e: e, vrpSet: make(map[types.RouteKey]struct{})}
	for _, p := range d.VRPPrefixes() {
		e.table.KeysWithin(p, func(k types.RouteKey) {
			if _, ok := rv.vrpSet[k]; !ok {
				rv.vrpSet[k] = struct{}{}
				rv.vrpKeys = append(rv.vrpKeys, k)
			}
		})
	}
	rv.Candidates = len(rv.vrpKeys)
	if len(d.ASPACustomers) > 0 {
		rv.aspaScan = e.table.NewMatchScan(pathContainsAny(d.ASPACustomers))
	}
	return rv
}

// pathContainsAny returns a predicate reporting whether a route's AS_PATH
// holds any of asns. It reads the route in place.
func pathContainsAny(asns []uint32) func(*types.Route) bool {
	if len(asns) <= 16 {
		return func(r *types.Route) bool {
			for _, a := range r.ASPath {
				if slices.Contains(asns, a) {
					return true
				}
			}
			return false
		}
	}
	set := make(map[uint32]struct{}, len(asns))
	for _, a := range asns {
		set[a] = struct{}{}
	}
	return func(r *types.Route) bool {
		for _, a := range r.ASPath {
			if _, ok := set[a]; ok {
				return true
			}
		}
		return false
	}
}

// Step revalidates up to budget routes, or reads one shard for the ASPA scan,
// and reports whether the pass is done.
func (rv *Revalidation) Step(budget int) bool {
	if rv.Full {
		routes := rv.scan.Next(budget)
		for _, r := range routes {
			rv.Candidates++
			rv.revalidate(r)
		}
		return len(routes) < budget
	}
	for ; budget > 0; budget-- {
		switch {
		case len(rv.pending) > 0:
			r := rv.pending[0]
			rv.pending = rv.pending[1:]
			rv.revalidate(r)
		case len(rv.vrpKeys) > 0:
			k := rv.vrpKeys[0]
			rv.vrpKeys = rv.vrpKeys[1:]
			if r := rv.e.table.Get(k); r != nil {
				rv.revalidate(r)
			}
		case rv.aspaScan != nil:
			// One shard is this step's work.
			rv.stepASPAScan()
			return false
		default:
			return true
		}
	}
	return len(rv.pending) == 0 && len(rv.vrpKeys) == 0 && rv.aspaScan == nil
}

// stepASPAScan reads the next shard and queues its matches that the VRP part
// of the pass did not already cover.
func (rv *Revalidation) stepASPAScan() {
	start := time.Now()
	matched, examined, done := rv.aspaScan.Next()
	for _, r := range matched {
		if _, ok := rv.vrpSet[r.Key()]; ok {
			continue
		}
		rv.pending = append(rv.pending, r)
		rv.Candidates++
	}
	rv.ASPAScanned += examined
	rv.ASPAScanTime += time.Since(start)
	if done {
		rv.aspaScan = nil
	}
}

// revalidate re-runs validation on r, a route the table held when the pass
// read it, and replaces it if a result changed.
func (rv *Revalidation) revalidate(r *types.Route) {
	rv.Checked++
	updated, changed := rv.e.Revalidated(r)
	if !changed {
		return
	}
	if rv.e.table.Replace(r, &updated) {
		rv.Changed++
	} else {
		rv.Skipped++
	}
}
