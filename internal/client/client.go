package client

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/dns-over-minecraft/dns-over-minecraft/internal/cache"
	"github.com/dns-over-minecraft/dns-over-minecraft/internal/dnscodec"
	"github.com/dns-over-minecraft/dns-over-minecraft/internal/mc"
	"github.com/dns-over-minecraft/dns-over-minecraft/internal/vpndns"
	"github.com/miekg/dns"
)

// QueryFunc performs a single DNS query against one dnsmc server.
type QueryFunc func(serverAddress, suffix string, queryMessage *dns.Msg) (*dns.Msg, error)

// vpnQueryFunc performs a single DNS query against a list of VPN DNS servers.
type vpnQueryFunc func(servers []vpndns.Server, queryMessage *dns.Msg) (*dns.Msg, error)

// vpnTimeout bounds a single exchange against a VPN DNS server.
const vpnTimeout = 2 * time.Second

// Client is a caching DNS client that forwards queries to one or more
// dnsmc servers over the Minecraft protocol. When a VPN connection advertises
// DNS servers, those are queried first.
type Client struct {
	cacheStore *cache.Cache
	servers    []string
	suffix     string
	queryFunc  QueryFunc

	// vpnDNS supplies DNS servers of the currently active VPN connections.
	// When non-nil and yielding servers, they are tried before the Minecraft
	// path. A nil value disables VPN DNS (today's behaviour).
	vpnDNS Provider
	// vpnQuery performs the actual exchange against VPN servers. Swappable for
	// tests; defaults to queryVpn.
	vpnQuery vpnQueryFunc
	// allowVpnFallback controls behaviour when all VPN DNS servers fail: true
	// falls back to the Minecraft path, false returns SERVFAIL (no leak).
	allowVpnFallback bool

	mutex      sync.Mutex
	nextServer int
}

// Provider is the minimal surface the client needs from a VPN DNS source.
type Provider interface {
	Servers() []vpndns.Server
}

func New(servers []string, suffix string, passphrase string, cacheStore *cache.Cache, queryFunc QueryFunc) *Client {
	if len(servers) == 0 {
		servers = []string{"127.0.0.1:25565"}
	}
	if queryFunc == nil {
		clientPassphrase := passphrase
		queryFunc = func(serverAddress, serverSuffix string, queryMessage *dns.Msg) (*dns.Msg, error) {
			return mc.Query(serverAddress, serverSuffix, clientPassphrase, queryMessage)
		}
	}
	clientInstance := &Client{cacheStore: cacheStore, servers: servers, suffix: suffix, queryFunc: queryFunc}
	clientInstance.vpnQuery = clientInstance.queryVpn
	return clientInstance
}

// SetVPN configures VPN DNS discovery. provider may be nil to disable it.
func (clientInstance *Client) SetVPN(provider Provider, allowFallbackToTunnel bool) {
	clientInstance.vpnDNS = provider
	clientInstance.allowVpnFallback = allowFallbackToTunnel
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

	// Query active VPN DNS servers first (if any). On success use the answer;
	// on total failure either fall back to the Minecraft path or fail closed.
	if clientInstance.vpnDNS != nil {
		if vpnServers := clientInstance.vpnDNS.Servers(); len(vpnServers) > 0 {
			log.Printf("dnsmc client: %s %s -> vpn dns (servers=%v)",
				question.Name, dns.TypeToString[question.Qtype], vpnServers)
			if vpnResponse, err := clientInstance.vpnQuery(vpnServers, queryMessage); err == nil {
				log.Printf("dnsmc client: %s answered via vpn dns", question.Name)
				if queryMessage.IsEdns0() == nil {
					dnscodec.StripOPT(vpnResponse)
				}
				if clientInstance.cacheStore != nil {
					clientInstance.cacheStore.Set(question, vpnResponse)
				}
				return vpnResponse, nil
			} else {
				log.Printf("dnsmc client: vpn dns unreachable (%v); %s", err, vpnFallbackNote(clientInstance.allowVpnFallback))
				if !clientInstance.allowVpnFallback {
					failureResponse := new(dns.Msg)
					failureResponse.SetReply(queryMessage)
					failureResponse.Rcode = dns.RcodeServerFailure
					return failureResponse, nil
				}
			}
		}
	}

	var lastError error
	for attempt := 0; attempt < len(clientInstance.servers); attempt++ {
		serverAddress := clientInstance.pickServer()
		responseMessage, err := clientInstance.queryFunc(serverAddress, clientInstance.suffix, queryMessage)
		if err == nil {
			if queryMessage.IsEdns0() == nil {
				dnscodec.StripOPT(responseMessage)
			}
			if clientInstance.cacheStore != nil {
				clientInstance.cacheStore.Set(question, responseMessage)
			}
			return responseMessage, nil
		}
		lastError = err
		log.Printf("dnsmc client: server %s unreachable: %v", serverAddress, err)
	}
	failureResponse := new(dns.Msg)
	failureResponse.SetReply(queryMessage)
	failureResponse.Rcode = dns.RcodeServerFailure
	return failureResponse, lastError
}

func vpnFallbackNote(allowFallback bool) string {
	if allowFallback {
		return "falling back to dnsmc servers"
	}
	return "failing closed (no fallback to avoid leaking internal names)"
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
