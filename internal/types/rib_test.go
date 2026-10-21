package types

import (
	"slices"
	"testing"
)

// RIB names are RIBType.String's; pre-policy and post-policy are accepted
// for the Adj-RIB-In, and anything else is an error.
func TestParseRIBTypeAliases(t *testing.T) {
	for name, want := range map[string]RIBType{
		"adj-rib-in-pre": AdjRIBInPre, "pre-policy": AdjRIBInPre,
		"adj-rib-in-post": AdjRIBInPost, "post-policy": AdjRIBInPost,
		"loc-rib": LocRIB, "adj-rib-out-pre": AdjRIBOutPre, "adj-rib-out-post": AdjRIBOutPost,
	} {
		if got, err := ParseRIBType(name); err != nil || got != want {
			t.Errorf("ParseRIBType(%q) = %s, %v; want %s", name, got, err, want)
		}
	}
	for _, name := range []string{"", "adj-rib-in", "Loc-RIB", "locrib"} {
		if _, err := ParseRIBType(name); err == nil {
			t.Errorf("ParseRIBType(%q): no error", name)
		}
	}
	for _, r := range AllRIBTypes {
		if got, _ := ParseRIBType(r.String()); got != r {
			t.Errorf("%s does not round-trip", r)
		}
	}
}

func TestRIBSet(t *testing.T) {
	if got := DefaultView.Names(); !slices.Equal(got, []string{"adj-rib-in-pre", "loc-rib"}) {
		t.Errorf("DefaultView = %v, want [adj-rib-in-pre loc-rib]", got)
	}
	for _, r := range AllRIBTypes {
		if want := r == AdjRIBInPre || r == LocRIB; DefaultView.Has(r) != want {
			t.Errorf("DefaultView.Has(%s) = %v, want %v", r, !want, want)
		}
	}
	s, err := ParseRIBSet([]string{"post-policy", "loc-rib", "adj-rib-in-post"})
	if err != nil || s != RIBSetOf(AdjRIBInPost, LocRIB) {
		t.Errorf("ParseRIBSet = %v, %v; want adj-rib-in-post and loc-rib", s.Names(), err)
	}
	if _, err := ParseRIBSet(nil); err == nil {
		t.Error("ParseRIBSet(nil): no error")
	}
	if _, err := ParseRIBSet([]string{"loc-rib", "nope"}); err == nil {
		t.Error("ParseRIBSet with an unknown name: no error")
	}
}

func TestPeerTypeName(t *testing.T) {
	for typ, want := range map[uint8]string{0: "global", 1: "rd", 2: "local", 3: "loc-rib", 9: "unknown(9)"} {
		if got := PeerTypeName(typ); got != want {
			t.Errorf("PeerTypeName(%d) = %q, want %q", typ, got, want)
		}
	}
}

// RD types 0 and 2 with the same numbers are two instances: their text, used
// as a metric label and a cooldown key, differs.
func TestFormatRDTypes0And2Apart(t *testing.T) {
	t0, t2 := FormatRD(0x0000_fde8_00000001), FormatRD(0x0002_0000_fde8_0001)
	if t0 != "65000:1" || t2 != "65000L:1" {
		t.Errorf("type 0 %q, type 2 %q; want 65000:1 and 65000L:1", t0, t2)
	}
}
