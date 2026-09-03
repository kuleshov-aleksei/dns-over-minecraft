package resolver

import (
	"sort"
)

type Snapshot struct {
	Total       int64
	CacheHits   int64
	CacheMisses int64
}

type DomainCount struct {
	Name  string
	Count int64
}

type resolverStats struct {
	total         int64
	cacheHits     int64
	cacheMisses   int64
	domainsAll    map[string]int64
	domainsWindow map[string]int64
}

func (resolverInstance *Resolver) recordTotal() {
	resolverInstance.statsMutex.Lock()
	resolverInstance.stats.total++
	resolverInstance.statsMutex.Unlock()
}

func (resolverInstance *Resolver) recordCacheHit() {
	resolverInstance.statsMutex.Lock()
	resolverInstance.stats.cacheHits++
	resolverInstance.statsMutex.Unlock()
}

func (resolverInstance *Resolver) recordCacheMiss() {
	resolverInstance.statsMutex.Lock()
	resolverInstance.stats.cacheMisses++
	resolverInstance.statsMutex.Unlock()
}

func (resolverInstance *Resolver) recordDomain(domainName string) {
	resolverInstance.statsMutex.Lock()
	resolverInstance.stats.domainsAll[domainName]++
	resolverInstance.stats.domainsWindow[domainName]++
	resolverInstance.statsMutex.Unlock()
}

func (resolverInstance *Resolver) TakeWindow() Snapshot {
	resolverInstance.statsMutex.Lock()
	defer resolverInstance.statsMutex.Unlock()
	snapshot := Snapshot{
		Total:       resolverInstance.stats.total,
		CacheHits:   resolverInstance.stats.cacheHits,
		CacheMisses: resolverInstance.stats.cacheMisses,
	}
	resolverInstance.stats.total = 0
	resolverInstance.stats.cacheHits = 0
	resolverInstance.stats.cacheMisses = 0
	return snapshot
}

func (resolverInstance *Resolver) DomainStats(limit int) (allTime []DomainCount, lastWindow []DomainCount) {
	resolverInstance.statsMutex.Lock()
	defer resolverInstance.statsMutex.Unlock()
	allTime = topDomains(resolverInstance.stats.domainsAll, limit)
	lastWindow = topDomains(resolverInstance.stats.domainsWindow, limit)
	resolverInstance.stats.domainsWindow = make(map[string]int64)
	return allTime, lastWindow
}

func topDomains(domainCounts map[string]int64, limit int) []DomainCount {
	entries := make([]DomainCount, 0, len(domainCounts))
	for domainName, count := range domainCounts {
		entries = append(entries, DomainCount{Name: domainName, Count: count})
	}
	sort.Slice(entries, func(firstIndex, secondIndex int) bool {
		if entries[firstIndex].Count != entries[secondIndex].Count {
			return entries[firstIndex].Count > entries[secondIndex].Count
		}
		return entries[firstIndex].Name < entries[secondIndex].Name
	})
	if limit < len(entries) {
		entries = entries[:limit]
	}
	return entries
}