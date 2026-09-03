package cache

import (
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type entry struct {
	message   *dns.Msg
	storedAt  time.Time
	expiresAt time.Time
}

type Cache struct {
	mutex       sync.RWMutex
	items       map[string]*entry
	ttl         time.Duration
	negativeTTL time.Duration
	maxSize     int
}

func New(cacheSize int, cacheTTL, negativeCacheTTL time.Duration) *Cache {
	if cacheSize <= 0 {
		cacheSize = 2048
	}
	if cacheTTL <= 0 {
		cacheTTL = 5 * time.Minute
	}
	if negativeCacheTTL <= 0 {
		negativeCacheTTL = 30 * time.Second
	}
	return &Cache{
		items:       make(map[string]*entry, cacheSize),
		ttl:         cacheTTL,
		negativeTTL: negativeCacheTTL,
		maxSize:     cacheSize,
	}
}

func cacheKey(question dns.Question) string {
	return strings.ToLower(dns.Fqdn(question.Name)) + "/" + dns.ClassToString[question.Qclass] + "/" + dns.TypeToString[question.Qtype]
}

func (cacheInstance *Cache) Get(question dns.Question) (*dns.Msg, bool) {
	cacheInstance.mutex.RLock()
	cachedEntry, exists := cacheInstance.items[cacheKey(question)]
	cacheInstance.mutex.RUnlock()
	if !exists {
		return nil, false
	}
	now := time.Now()
	if now.After(cachedEntry.expiresAt) {
		cacheInstance.mutex.Lock()
		delete(cacheInstance.items, cacheKey(question))
		cacheInstance.mutex.Unlock()
		return nil, false
	}
	elapsedSeconds := uint32(now.Sub(cachedEntry.storedAt).Seconds())
	if elapsedSeconds > 0 {
		for _, resourceRecord := range cachedEntry.message.Answer {
			resourceRecord.Header().Ttl = decrementedTTL(resourceRecord.Header().Ttl, elapsedSeconds)
		}
		for _, resourceRecord := range cachedEntry.message.Ns {
			resourceRecord.Header().Ttl = decrementedTTL(resourceRecord.Header().Ttl, elapsedSeconds)
		}
		for _, resourceRecord := range cachedEntry.message.Extra {
			resourceRecord.Header().Ttl = decrementedTTL(resourceRecord.Header().Ttl, elapsedSeconds)
		}
	}
	copiedMessage := cachedEntry.message.Copy()
	copiedMessage.Id = 0 // caller will set
	return copiedMessage, true
}

func decrementedTTL(currentTTL, elapsedSeconds uint32) uint32 {
	if currentTTL <= elapsedSeconds {
		return 0
	}
	return currentTTL - elapsedSeconds
}

func (cacheInstance *Cache) Set(question dns.Question, responseMessage *dns.Msg) {
	if responseMessage == nil || responseMessage.Rcode == dns.RcodeNameError {
		return
	}
	computedTTL := cacheInstance.ttl
	if len(responseMessage.Answer) > 0 {
		minimumTTL := uint32(computedTTL.Seconds())
		for _, resourceRecord := range responseMessage.Answer {
			if resourceRecord.Header().Ttl < minimumTTL {
				minimumTTL = resourceRecord.Header().Ttl
			}
		}
		if time.Duration(minimumTTL)*time.Second < computedTTL {
			computedTTL = time.Duration(minimumTTL) * time.Second
		}
	} else {
		computedTTL = cacheInstance.negativeTTL
	}
	if computedTTL <= 0 {
		computedTTL = cacheInstance.negativeTTL
	}
	cacheInstance.mutex.Lock()
	defer cacheInstance.mutex.Unlock()
	if len(cacheInstance.items) >= cacheInstance.maxSize {
		for key := range cacheInstance.items {
			delete(cacheInstance.items, key)
			break
		}
	}
	copiedMessage := responseMessage.Copy()
	now := time.Now()
	cacheInstance.items[cacheKey(question)] = &entry{message: copiedMessage, storedAt: now, expiresAt: now.Add(computedTTL)}
}
