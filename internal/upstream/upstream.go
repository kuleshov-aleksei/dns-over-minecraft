package upstream

import (
	"context"
	"sort"

	"github.com/miekg/dns"
)

type Upstream interface {
	Name() string
	Priority() int
	Exchange(requestContext context.Context, queryMessage *dns.Msg) (*dns.Msg, error)
}

type Pool struct {
	upstreamList []Upstream
}

func NewPool(upstreamList []Upstream) *Pool {
	sort.Slice(upstreamList, func(firstIndex, secondIndex int) bool {
		if upstreamList[firstIndex].Priority() == upstreamList[secondIndex].Priority() {
			return upstreamList[firstIndex].Name() < upstreamList[secondIndex].Name()
		}
		return upstreamList[firstIndex].Priority() > upstreamList[secondIndex].Priority()
	})
	return &Pool{upstreamList: upstreamList}
}

func (poolInstance *Pool) Exchange(requestContext context.Context, queryMessage *dns.Msg) (*dns.Msg, error) {
	var lastError error
	for _, upstreamInstance := range poolInstance.upstreamList {
		select {
		case <-requestContext.Done():
			return nil, requestContext.Err()
		default:
		}
		responseMessage, err := upstreamInstance.Exchange(requestContext, queryMessage)
		if err == nil && responseMessage != nil {
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

func (poolInstance *Pool) List() []Upstream { return poolInstance.upstreamList }
