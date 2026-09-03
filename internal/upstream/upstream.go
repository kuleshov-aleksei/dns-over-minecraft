package upstream

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type Upstream interface {
	Name() string
	Priority() int
	Exchange(requestContext context.Context, queryMessage *dns.Msg) (*dns.Msg, error)
}

// ewmaAlpha is the smoothing factor for per-upstream response-time tracking.
// Higher priority tiers are always tried first; within a tier, upstreams are
// ordered by their EWMA response time (faster first).
const ewmaAlpha = 0.3

type Pool struct {
	mutex        sync.RWMutex
	upstreamList []Upstream
	ewma         map[string]float64
}

func NewPool(upstreamList []Upstream) *Pool {
	pool := &Pool{
		upstreamList: append([]Upstream(nil), upstreamList...),
		ewma:         make(map[string]float64, len(upstreamList)),
	}
	sort.Slice(pool.upstreamList, pool.less)
	return pool
}

// less reports whether upstream i should be tried before upstream j: higher
// priority first, then faster EWMA response time, then name for determinism.
func (poolInstance *Pool) less(firstIndex, secondIndex int) bool {
	firstUpstream := poolInstance.upstreamList[firstIndex]
	secondUpstream := poolInstance.upstreamList[secondIndex]
	if firstUpstream.Priority() != secondUpstream.Priority() {
		return firstUpstream.Priority() > secondUpstream.Priority()
	}
	firstEwma := poolInstance.ewma[firstUpstream.Name()]
	secondEwma := poolInstance.ewma[secondUpstream.Name()]
	if firstEwma != secondEwma {
		return firstEwma < secondEwma
	}
	return firstUpstream.Name() < secondUpstream.Name()
}

func (poolInstance *Pool) Exchange(requestContext context.Context, queryMessage *dns.Msg) (*dns.Msg, error) {
	poolInstance.mutex.RLock()
	upstreamSnapshot := append([]Upstream(nil), poolInstance.upstreamList...)
	poolInstance.mutex.RUnlock()

	var lastError error
	for _, upstreamInstance := range upstreamSnapshot {
		select {
		case <-requestContext.Done():
			return nil, requestContext.Err()
		default:
		}
		queryStartTime := time.Now()
		responseMessage, err := upstreamInstance.Exchange(requestContext, queryMessage)
		if err == nil && responseMessage != nil {
			poolInstance.recordSuccess(upstreamInstance, time.Since(queryStartTime))
			return responseMessage, nil
		}
		if err != nil {
			lastError = err
		} else {
			lastError = nil
		}
	}
	if lastError != nil {
		return nil, lastError
	}
	return nil, context.DeadlineExceeded
}

// recordSuccess updates the EWMA response time for an upstream and reorders
// the pool so faster upstreams within the same priority tier are tried first.
func (poolInstance *Pool) recordSuccess(upstreamInstance Upstream, elapsed time.Duration) {
	sampleMilliseconds := float64(elapsed) / float64(time.Millisecond)
	poolInstance.mutex.Lock()
	defer poolInstance.mutex.Unlock()
	if previousValue, exists := poolInstance.ewma[upstreamInstance.Name()]; exists {
		poolInstance.ewma[upstreamInstance.Name()] = ewmaAlpha*sampleMilliseconds + (1-ewmaAlpha)*previousValue
	} else {
		poolInstance.ewma[upstreamInstance.Name()] = sampleMilliseconds
	}
	sort.Slice(poolInstance.upstreamList, poolInstance.less)
}

func (poolInstance *Pool) List() []Upstream {
	poolInstance.mutex.RLock()
	defer poolInstance.mutex.RUnlock()
	return append([]Upstream(nil), poolInstance.upstreamList...)
}
