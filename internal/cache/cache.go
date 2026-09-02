package cache

import (
	"sync"
	"time"

	"github.com/miekg/dns"
)

type entry struct {
	message   *dns.Msg
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
	return question.Name + "/" + dns.ClassToString[question.Qclass] + "/" + dns.TypeToString[question.Qtype]
}

func (cacheInstance *Cache) Get(question dns.Question) (*dns.Msg, bool) {
	cacheInstance.mutex.RLock()
	cachedEntry, exists := cacheInstance.items[cacheKey(question)]
	cacheInstance.mutex.RUnlock()
	if !exists {
		return nil, false
	}
	if time.Now().After(cachedEntry.expiresAt) {
		cacheInstance.mutex.Lock()
		delete(cacheInstance.items, cacheKey(question))
		cacheInstance.mutex.Unlock()
		return nil, false
	}
	copiedMessage := cachedEntry.message.Copy()
	copiedMessage.Id = 0 // caller will set
	return copiedMessage, true
}

func (cacheInstance *Cache) Set(question dns.Question, responseMessage *dns.Msg) {
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
	cacheInstance.items[cacheKey(question)] = &entry{message: copiedMessage, expiresAt: time.Now().Add(computedTTL)}
}
