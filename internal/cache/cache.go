package cache

import (
	"container/list"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type entry struct {
	key       string
	message   *dns.Msg
	storedAt  time.Time
	expiresAt time.Time
	element   *list.Element
}

type Cache struct {
	mutex       sync.RWMutex
	items       map[string]*entry
	lru         *list.List
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
		lru:         list.New(),
		ttl:         cacheTTL,
		negativeTTL: negativeCacheTTL,
		maxSize:     cacheSize,
	}
}

func cacheKey(question dns.Question) string {
	return strings.ToLower(dns.Fqdn(question.Name)) + "/" + dns.ClassToString[question.Qclass] + "/" + dns.TypeToString[question.Qtype]
}

func (cacheInstance *Cache) Get(question dns.Question) (*dns.Msg, bool) {
	key := cacheKey(question)
	cacheInstance.mutex.RLock()
	cachedEntry, exists := cacheInstance.items[key]
	cacheInstance.mutex.RUnlock()
	if !exists {
		return nil, false
	}
	now := time.Now()
	if now.After(cachedEntry.expiresAt) {
		cacheInstance.mutex.Lock()
		cacheInstance.removeLocked(key)
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
	cacheInstance.mutex.Lock()
	cacheInstance.lru.MoveToFront(cachedEntry.element)
	cacheInstance.mutex.Unlock()
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
	key := cacheKey(question)
	copiedMessage := responseMessage.Copy()
	now := time.Now()
	cacheInstance.mutex.Lock()
	defer cacheInstance.mutex.Unlock()
	if existingEntry, exists := cacheInstance.items[key]; exists {
		cacheInstance.lru.Remove(existingEntry.element)
	}
	cachedEntry := &entry{key: key, message: copiedMessage, storedAt: now, expiresAt: now.Add(computedTTL)}
	cachedEntry.element = cacheInstance.lru.PushFront(cachedEntry)
	cacheInstance.items[key] = cachedEntry
	cacheInstance.evictLocked()
}

// removeLocked deletes a single entry by key, keeping the LRU list consistent.
// Caller must hold mutex.
func (cacheInstance *Cache) removeLocked(key string) {
	if cachedEntry, exists := cacheInstance.items[key]; exists {
		cacheInstance.lru.Remove(cachedEntry.element)
		delete(cacheInstance.items, key)
	}
}

// evictLocked drops entries until the cache fits maxSize: expired entries are
// removed first (scanning from the least-recently-used end), then the
// least-recently-used entry. Caller must hold mutex.
func (cacheInstance *Cache) evictLocked() {
	now := time.Now()
	for len(cacheInstance.items) > cacheInstance.maxSize {
		element := cacheInstance.lru.Back()
		if element == nil {
			return
		}
		for candidate := element; candidate != nil; candidate = candidate.Prev() {
			if now.After(candidate.Value.(*entry).expiresAt) {
				element = candidate
				break
			}
		}
		cacheInstance.removeElementLocked(element)
	}
}

func (cacheInstance *Cache) removeElementLocked(element *list.Element) {
	cachedEntry := element.Value.(*entry)
	cacheInstance.lru.Remove(element)
	delete(cacheInstance.items, cachedEntry.key)
}