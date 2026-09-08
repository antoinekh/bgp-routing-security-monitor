package ripestat

import (
	"sync"
	"time"
)

// tokenBucket is a per-instance rate limiter. Capacity equals the per-minute
// budget, so a burst may consume a full minute's allowance at once and then
// refills continuously at budget/60 per second.
//
// It never blocks: allow reports whether the caller may proceed, and a
// rejection surfaces as ErrRateLimited rather than latency on the caller.
type tokenBucket struct {
	mu           sync.Mutex
	capacity     float64
	tokens       float64
	refillPerSec float64
	last         time.Time
	now          func() time.Time
}

func newTokenBucket(perMinute float64, now func() time.Time) *tokenBucket {
	return &tokenBucket{
		capacity:     perMinute,
		tokens:       perMinute,
		refillPerSec: perMinute / 60,
		last:         now(),
		now:          now,
	}
}

// allow consumes one token, reporting false when none is available.
func (b *tokenBucket) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()
	if elapsed := now.Sub(b.last); elapsed > 0 {
		b.tokens += elapsed.Seconds() * b.refillPerSec
		if b.tokens > b.capacity {
			b.tokens = b.capacity
		}
		b.last = now
	}

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
