package store

import (
	"testing"
)

// BenchmarkFindCovering looks up route prefixes (about 60% under a ROA,
// a fifth IPv6) in a warm store of 750k VRPs.
//
//	go test -run '^$' -bench FindCovering -benchmem ./internal/rtr/store/
func BenchmarkFindCovering(b *testing.B) {
	for _, ds := range datasets(b) {
		b.Run(ds.name, func(b *testing.B) {
			s := NewVRPStore()
			s.ReplaceAll(ds.VRPs, 1, 1)
			for _, p := range ds.Routes { // warm
				s.FindCovering(p)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				s.FindCovering(ds.Routes[i%len(ds.Routes)])
			}
		})
	}
}

// BenchmarkRebuildIndex is the index rebuild each RTR End of Data pays. It
// runs off to the side: lookups go on using the previous index meanwhile.
func BenchmarkRebuildIndex(b *testing.B) {
	for _, ds := range datasets(b) {
		b.Run(ds.name, func(b *testing.B) {
			s := NewVRPStore()
			s.ReplaceAll(ds.VRPs, 1, 1)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				s.RebuildIndex()
			}
		})
	}
}

// BenchmarkRebuildIndexOld is the same rebuild in the old string-keyed index
// (refStore), to compare like for like in one run.
func BenchmarkRebuildIndexOld(b *testing.B) {
	for _, ds := range datasets(b) {
		b.Run(ds.name, func(b *testing.B) {
			s := newRefStore()
			s.ReplaceAll(ds.VRPs)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				s.rebuildIndex()
			}
		})
	}
}

// BenchmarkFindCoveringOld is the old lookup, likewise.
func BenchmarkFindCoveringOld(b *testing.B) {
	for _, ds := range datasets(b) {
		b.Run(ds.name, func(b *testing.B) {
			s := newRefStore()
			s.ReplaceAll(ds.VRPs)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				s.FindCovering(ds.Routes[i%len(ds.Routes)])
			}
		})
	}
}
