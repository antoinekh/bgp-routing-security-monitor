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
//  1. Find all VRPs whose prefix covers the route's prefix.
//  2. If no covering VRPs exist → NotFound.
//  3. If any covering VRP matches the origin ASN AND the route's
//     prefix length ≤ VRP's maxLength → Valid.
//  4. Otherwise → Invalid.
func (a *Annotator) Validate(route *types.Route) types.ROVResult {
	originASN := route.OriginASN()
	if originASN == 0 {
		return types.ROVResult{
			State:  types.ROVNotFound,
			Reason: "no origin ASN in AS_PATH",
		}
	}

	covering := a.vrpStore.FindCovering(route.Prefix)

	if len(covering) == 0 {
		return types.ROVResult{
			State:  types.ROVNotFound,
			Reason: "no covering VRPs found",
		}
	}

	routePrefixLen := route.Prefix.Bits()

	for _, vrp := range covering {
		if vrp.ASN == originASN && routePrefixLen <= int(vrp.MaxLength) {
			return types.ROVResult{
				State:       types.ROVValid,
				MatchedVRPs: covering,
				Reason:      validReason(vrp),
			}
		}
	}

	return types.ROVResult{
		State:       types.ROVInvalid,
		MatchedVRPs: covering,
		Reason:      invalidReason(originASN),
	}
}

// validReason and invalidReason build the Reason strings with a single
// allocation; fmt.Sprintf boxed each argument as well. The text is the same:
// "matches VRP {%s, AS%d, /%d}" and "origin AS%d not authorized by any
// covering VRP".
func validReason(v types.VRP) string {
	var buf [96]byte
	b := append(buf[:0], "matches VRP {"...)
	b = v.Prefix.AppendTo(b)
	b = append(b, ", AS"...)
	b = strconv.AppendUint(b, uint64(v.ASN), 10)
	b = append(b, ", /"...)
	b = strconv.AppendUint(b, uint64(v.MaxLength), 10)
	b = append(b, '}')
	return string(b)
}

func invalidReason(originASN uint32) string {
	var buf [64]byte
	b := append(buf[:0], "origin AS"...)
	b = strconv.AppendUint(b, uint64(originASN), 10)
	b = append(b, " not authorized by any covering VRP"...)
	return string(b)
}
