package rov

import (
	"strconv"

	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// Annotator performs Route Origin Validation per RFC 6811.
type Annotator struct {
	vrpStore *store.VRPStore
}

// NewAnnotator creates a ROV annotator backed by the given VRP store.
func NewAnnotator(vrpStore *store.VRPStore) *Annotator {
	return &Annotator{vrpStore: vrpStore}
}

// Validate performs ROV on a single route and returns the result.
//
// Algorithm (RFC 6811 §2):
//  1. Take the route's origin AS (types.Route.OriginAS): the last AS of a
//     final AS_SEQUENCE; NONE after a final AS_SET; the router's own AS for
//     an empty AS_PATH or one ending in a confederation segment.
//  2. Find all VRPs whose prefix covers the route's prefix.
//  3. If no covering VRPs exist → NotFound.
//  4. If any covering VRP matches the origin ASN AND the route's
//     prefix length ≤ VRP's maxLength → Valid. A NONE origin matches none.
//  5. Otherwise → Invalid.
//
// An origin that is the router's own AS is validated like any other, and
// the Reason says where it came from. If RAVEN does not know that AS the
// route is NotFound (localASUnknownReason).
func (a *Annotator) Validate(route *types.Route) types.ROVResult {
	originASN, src := route.OriginAS()
	if src == types.OriginNone {
		covering := a.vrpStore.FindCovering(route.Prefix)
		if len(covering) == 0 {
			return types.ROVResult{State: types.ROVNotFound, Reason: noneOriginNotFoundReason}
		}
		return types.ROVResult{State: types.ROVInvalid, MatchedVRPs: covering, Reason: noneOriginInvalidReason}
	}
	if originASN == 0 {
		reason := "no origin ASN in AS_PATH"
		if src != types.OriginFromPath {
			reason = localASUnknownReason
		}
		return types.ROVResult{
			State:  types.ROVNotFound,
			Reason: reason,
		}
	}
	note := localOriginNotes[src]

	covering := a.vrpStore.FindCovering(route.Prefix)

	if len(covering) == 0 {
		reason := "no covering VRPs found"
		if note != "" {
			reason = localOriginNotFoundReasons[src]
		}
		return types.ROVResult{
			State:  types.ROVNotFound,
			Reason: reason,
		}
	}

	routePrefixLen := route.Prefix.Bits()

	for _, vrp := range covering {
		if vrp.ASN == originASN && routePrefixLen <= int(vrp.MaxLength) {
			return types.ROVResult{
				State:       types.ROVValid,
				MatchedVRPs: covering,
				Reason:      validReason(vrp, note),
			}
		}
	}

	return types.ROVResult{
		State:       types.ROVInvalid,
		MatchedVRPs: covering,
		Reason:      invalidReason(originASN, note),
	}
}

// localASUnknownReason is the ROV Reason when the origin is the router's own
// AS (an empty AS_PATH, or one ending in a confederation segment; RFC 6811
// §2) and RAVEN does not know it: no Peer Up OPEN gave it.
const localASUnknownReason = "origin unknown: local AS not known"

// localOriginNotes say, at the end of the ROV Reason, why the origin is the
// router's own AS (RFC 6811 §2), by types.OriginSource. RAVEN used to give
// such routes no origin and call them NotFound, wrongly citing §2 for the
// confederation case.
var localOriginNotes = [...]string{
	types.OriginLocalAS: "origin is the router's own AS: empty AS_PATH (RFC 6811 §2)",
	types.OriginLocalConfedID: "origin is the router's own AS, its confederation identifier: " +
		"empty AS_PATH (RFC 6811 §2)",
	types.OriginConfedID: "origin is the router's own AS, its confederation identifier: " +
		"AS_PATH ends in a confederation segment (RFC 6811 §2)",
	types.OriginConfedMember: "origin is the router's own AS, its member AS: AS_PATH ends in a " +
		"confederation segment (RFC 6811 §2) and the confederation identifier is not known",
}

// localOriginNotFoundReasons are the NotFound Reasons for those origins,
// built once so a NotFound result allocates nothing.
var localOriginNotFoundReasons = func() (r [len(localOriginNotes)]string) {
	for i, n := range localOriginNotes {
		if n != "" {
			r[i] = "no covering VRPs found; " + n
		}
	}
	return r
}()

// The ROV Reasons for a route whose AS_PATH ends in an AS_SET: its origin is
// NONE (RFC 6811 §2), Invalid under any covering VRP, NotFound otherwise.
// RAVEN used to take the set's last member as the origin, which a VRP could
// match.
const (
	noneOriginInvalidReason  = "origin is NONE: AS_PATH ends in an AS_SET (RFC 6811 §2), which no covering VRP can match"
	noneOriginNotFoundReason = "origin is NONE: AS_PATH ends in an AS_SET (RFC 6811 §2); no covering VRPs found"
)

// validReason and invalidReason build the Reason strings with a single
// allocation; fmt.Sprintf boxed each argument as well. The text is the same:
// "matches VRP {%s, AS%d, /%d}" and "origin AS%d not authorized by any
// covering VRP", followed by "; " and note if note is not empty.
func validReason(v types.VRP, note string) string {
	var buf [256]byte
	b := append(buf[:0], "matches VRP {"...)
	b = v.Prefix.AppendTo(b)
	b = append(b, ", AS"...)
	b = strconv.AppendUint(b, uint64(v.ASN), 10)
	b = append(b, ", /"...)
	b = strconv.AppendUint(b, uint64(v.MaxLength), 10)
	b = append(b, '}')
	return string(appendNote(b, note))
}

func invalidReason(originASN uint32, note string) string {
	var buf [256]byte
	b := append(buf[:0], "origin AS"...)
	b = strconv.AppendUint(b, uint64(originASN), 10)
	b = append(b, " not authorized by any covering VRP"...)
	return string(appendNote(b, note))
}

func appendNote(b []byte, note string) []byte {
	if note == "" {
		return b
	}
	b = append(b, "; "...)
	return append(b, note...)
}
