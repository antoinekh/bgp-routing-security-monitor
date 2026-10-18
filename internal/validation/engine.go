package validation

import (
	"slices"

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
// annotations. Called by the ingest pipeline for each new route, and by
// revalidation, so both pick the ASPA procedure the same way.
func (e *Engine) ValidateRoute(route *types.Route) {
	// ROV
	route.ROV = e.rovAnnotator.Validate(route)
	// ASPA, with the procedure for the peer the route was learned from
	sel := e.aspaSelector.Select(route.PeerAddr, route.PeerASN)
	route.ASPA = e.aspaAnnotator.ValidateSelection(route, sel)
	a := route.ASPA
	if int(a.Procedure) < 2 && int(a.ProcedureSource) < 3 && int(a.State) < 4 {
		e.aspaCount[a.Procedure][a.ProcedureSource][a.State].Inc()
	}
	// Combined posture
	route.SecurityPosture = types.ComputePosture(route.ROV.State, route.ASPA.State)
}

// Revalidated returns a copy of route with validation re-run against the
// current VRP and ASPA stores, and whether any annotation differs from
// route's. route itself is not modified: routes in the table are read
// concurrently and must never change in place.
func (e *Engine) Revalidated(route *types.Route) (types.Route, bool) {
	cp := *route
	e.ValidateRoute(&cp)
	return cp, !sameValidation(route, &cp)
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

// Revalidation is one pass re-running validation over every route in the
// table, after the VRP or ASPA store changed. It is applied a chunk at a time
// by the Route Table's single writer (the ingest loop), between ingest
// events.
//
// A route whose results changed is replaced by a revalidated copy, and only
// if the table still holds that route; one withdrawn or re-announced since
// the pass read it is skipped, since a re-announcement was validated on
// ingest against the current stores.
type Revalidation struct {
	e    *Engine
	scan *routetable.Scan

	Checked int // routes revalidated
	Changed int // routes replaced with new results
	Skipped int // routes with new results gone or replaced before they could be applied
}

// NewRevalidation starts a revalidation pass over the table.
func (e *Engine) NewRevalidation() *Revalidation {
	return &Revalidation{e: e, scan: e.table.NewScan()}
}

// Step revalidates up to budget routes and reports whether the pass is done.
func (rv *Revalidation) Step(budget int) bool {
	routes := rv.scan.Next(budget)
	for _, r := range routes {
		rv.Checked++
		updated, changed := rv.e.Revalidated(r)
		if !changed {
			continue
		}
		if rv.e.table.Replace(r, &updated) {
			rv.Changed++
		} else {
			rv.Skipped++
		}
	}
	return len(routes) < budget
}
