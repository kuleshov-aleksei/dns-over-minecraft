package cache

import (
	"sync"
	"time"

	"github.com/miekg/dns"
)

type entry struct {
	msg     *dns.Msg
	expires time.Time
}

type Cache struct {
	mu          sync.RWMutex
	items       map[string]*entry
	ttl         time.Duration
	negativeTTL time.Duration
	maxSize     int
}

func New(size int, ttl, negativeTTL time.Duration) *Cache {
	if size <= 0 {
		size = 2048
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	if negativeTTL <= 0 {
		negativeTTL = 30 * time.Second
	}
	return &Cache{
		items:       make(map[string]*entry, size),
		ttl:         ttl,
		negativeTTL: negativeTTL,
		maxSize:     size,
	}
}

func cacheKey(q dns.Question) string {
	return q.Name + "/" + dns.ClassToString[q.Qclass] + "/" + dns.TypeToString[q.Qtype]
}

func (c *Cache) Get(q dns.Question) (*dns.Msg, bool) {
	c.mu.RLock()
	e, ok := c.items[cacheKey(q)]
	c.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if time.Now().After(e.expires) {
		c.mu.Lock()
		delete(c.items, cacheKey(q))
		c.mu.Unlock()
		return nil, false
	}
	// return copy
	cp := e.msg.Copy()
	cp.Id = 0 // caller will set
	return cp, true
}

func (c *Cache) Set(q dns.Question, msg *dns.Msg) {
	ttl := c.ttl
	// use TTL from answer if present and smaller
	if len(msg.Answer) > 0 {
		minTTL := uint32(ttl.Seconds())
		for _, rr := range msg.Answer {
			if rr.Header().Ttl < minTTL {
				minTTL = rr.Header().Ttl
			}
		}
		if time.Duration(minTTL)*time.Second < ttl {
			ttl = time.Duration(minTTL) * time.Second
		}
	} else {
		// NXDOMAIN / empty answer uses negative TTL
		ttl = c.negativeTTL
	}
	if ttl <= 0 {
		ttl = c.negativeTTL
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.items) >= c.maxSize {
		// evict one random (oldest not tracked; simple delete first)
		for k := range c.items {
			delete(c.items, k)
			break
		}
	}
	// store copy
	cp := msg.Copy()
	c.items[cacheKey(q)] = &entry{msg: cp, expires: time.Now().Add(ttl)}
}
