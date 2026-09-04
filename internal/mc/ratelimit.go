package mc

import (
	"sync"
	"time"
)

// ipRateLimiter is a per-client-IP token bucket rate limiter with idle cleanup.
// Each Allow call consumes one token; tokens refill continuously at the
// configured rate. A zero/negative rate disables limiting (the caller simply
// does not construct a limiter).
type ipRateLimiter struct {
	mutex   sync.Mutex
	rate    float64
	burst   float64
	buckets map[string]*tokenBucket
}

type tokenBucket struct {
	tokens   float64
	lastTime time.Time
}

func newIPRateLimiter(queriesPerSecond int) *ipRateLimiter {
	if queriesPerSecond < 1 {
		queriesPerSecond = 1
	}
	return &ipRateLimiter{
		rate:    float64(queriesPerSecond),
		burst:   float64(queriesPerSecond),
		buckets: make(map[string]*tokenBucket),
	}
}

// Allow reports whether the client at ipAddress may proceed, consuming one token.
func (limiter *ipRateLimiter) Allow(ipAddress string) bool {
	limiter.mutex.Lock()
	defer limiter.mutex.Unlock()
	now := time.Now()
	bucket, exists := limiter.buckets[ipAddress]
	if !exists {
		bucket = &tokenBucket{tokens: limiter.burst, lastTime: now}
		limiter.buckets[ipAddress] = bucket
	} else {
		elapsed := now.Sub(bucket.lastTime).Seconds()
		bucket.tokens += elapsed * limiter.rate
		if bucket.tokens > limiter.burst {
			bucket.tokens = limiter.burst
		}
		bucket.lastTime = now
	}
	if bucket.tokens < 1 {
		return false
	}
	bucket.tokens--
	return true
}

// cleanup drops buckets idle for longer than idleTimeout so a long-running
// server does not retain an entry per abusive source IP.
func (limiter *ipRateLimiter) cleanup(idleTimeout time.Duration) {
	limiter.mutex.Lock()
	defer limiter.mutex.Unlock()
	cutoff := time.Now().Add(-idleTimeout)
	for address, bucket := range limiter.buckets {
		if bucket.lastTime.Before(cutoff) {
			delete(limiter.buckets, address)
		}
	}
}
