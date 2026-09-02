package resolver

import (
	"context"

	"github.com/dns-over-minecraft/dns-over-minecraft/internal/cache"
	"github.com/dns-over-minecraft/dns-over-minecraft/internal/records"
	"github.com/dns-over-minecraft/dns-over-minecraft/internal/upstream"
	"github.com/miekg/dns"
)

type Resolver struct {
	cacheStore  *cache.Cache
	recordStore *records.Store
	upstreamPool *upstream.Pool
}

func New(cacheStore *cache.Cache, recordStore *records.Store, upstreamPool *upstream.Pool) *Resolver {
	return &Resolver{cacheStore: cacheStore, recordStore: recordStore, upstreamPool: upstreamPool}
}

func (resolverInstance *Resolver) Resolve(requestContext context.Context, queryMessage *dns.Msg) (*dns.Msg, error) {
	if len(queryMessage.Question) == 0 {
		errorResponse := new(dns.Msg)
		errorResponse.SetReply(queryMessage)
		errorResponse.Rcode = dns.RcodeFormatError
		return errorResponse, nil
	}
	question := queryMessage.Question[0]

	if resolverInstance.cacheStore != nil {
		if cachedResponse, exists := resolverInstance.cacheStore.Get(question); exists {
			cachedResponse.Id = queryMessage.Id
			cachedResponse.Question = queryMessage.Question
			return cachedResponse, nil
		}
	}

	if resolverInstance.recordStore != nil {
		if resourceRecords, authoritative := resolverInstance.recordStore.Lookup(question); authoritative {
			responseMessage := new(dns.Msg)
			responseMessage.SetReply(queryMessage)
			responseMessage.Authoritative = true
			responseMessage.RecursionAvailable = true
			if len(resourceRecords) > 0 {
				responseMessage.Answer = resourceRecords
			}
			if resolverInstance.cacheStore != nil {
				resolverInstance.cacheStore.Set(question, responseMessage)
			}
			return responseMessage, nil
		}
	}

	if resolverInstance.upstreamPool == nil || len(resolverInstance.upstreamPool.List()) == 0 {
		errorResponse := new(dns.Msg)
		errorResponse.SetReply(queryMessage)
		errorResponse.Rcode = dns.RcodeServerFailure
		return errorResponse, nil
	}
	upstreamResponse, err := resolverInstance.upstreamPool.Exchange(requestContext, queryMessage)
	if err != nil {
		failureResponse := new(dns.Msg)
		failureResponse.SetReply(queryMessage)
		failureResponse.Rcode = dns.RcodeServerFailure
		return failureResponse, nil
	}
	if resolverInstance.cacheStore != nil {
		resolverInstance.cacheStore.Set(question, upstreamResponse)
	}
	return upstreamResponse, nil
}
