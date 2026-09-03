package client

import (
	"context"
	"sync"

	"github.com/dns-over-minecraft/dns-over-minecraft/internal/cache"
	"github.com/dns-over-minecraft/dns-over-minecraft/internal/mc"
	"github.com/miekg/dns"
)

// QueryFunc performs a single DNS query against one dnsmc server.
type QueryFunc func(serverAddress, suffix string, queryMessage *dns.Msg) (*dns.Msg, error)

// Client is a caching DNS client that forwards queries to one or more
// dnsmc servers over the Minecraft protocol.
type Client struct {
	cacheStore *cache.Cache
	servers    []string
	suffix     string
	queryFunc  QueryFunc

	mutex      sync.Mutex
	nextServer int
}

func New(servers []string, suffix string, cacheStore *cache.Cache, queryFunc QueryFunc) *Client {
	if len(servers) == 0 {
		servers = []string{"127.0.0.1:25565"}
	}
	if queryFunc == nil {
		queryFunc = mc.Query
	}
	return &Client{cacheStore: cacheStore, servers: servers, suffix: suffix, queryFunc: queryFunc}
}

func (clientInstance *Client) Resolve(requestContext context.Context, queryMessage *dns.Msg) (*dns.Msg, error) {
	if len(queryMessage.Question) == 0 {
		errorResponse := new(dns.Msg)
		errorResponse.SetReply(queryMessage)
		errorResponse.Rcode = dns.RcodeFormatError
		return errorResponse, nil
	}
	question := queryMessage.Question[0]

	if clientInstance.cacheStore != nil {
		if cachedResponse, exists := clientInstance.cacheStore.Get(question); exists {
			cachedResponse.Id = queryMessage.Id
			cachedResponse.Question = queryMessage.Question
			return cachedResponse, nil
		}
	}

	responseMessage, err := clientInstance.queryFunc(clientInstance.pickServer(), clientInstance.suffix, queryMessage)
	if err != nil {
		failureResponse := new(dns.Msg)
		failureResponse.SetReply(queryMessage)
		failureResponse.Rcode = dns.RcodeServerFailure
		return failureResponse, err
	}
	if clientInstance.cacheStore != nil {
		clientInstance.cacheStore.Set(question, responseMessage)
	}
	return responseMessage, nil
}

func (clientInstance *Client) pickServer() string {
	if len(clientInstance.servers) == 1 {
		return clientInstance.servers[0]
	}
	clientInstance.mutex.Lock()
	defer clientInstance.mutex.Unlock()
	serverAddress := clientInstance.servers[clientInstance.nextServer%len(clientInstance.servers)]
	clientInstance.nextServer++
	return serverAddress
}