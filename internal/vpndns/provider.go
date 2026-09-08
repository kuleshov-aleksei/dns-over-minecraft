package vpndns

import (
	"context"
	"log"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Server is a DNS server advertised by an active VPN connection.
type Server struct {
	// Addr is the DNS server in host:port form (port defaults to 53).
	Addr string
	// Priority is the NetworkManager DnsPriority (lower is more preferred).
	Priority int
}

// Provider supplies DNS servers from the currently active VPN connections.
// Implementations must never block on the query hot path: Servers returns a
// cached snapshot and is safe for concurrent use.
type Provider interface {
	Servers() []Server
}

// serverSource is the raw, bus-independent description of a VPN DNS server
// before formatting/ordering.
type serverSource struct {
	addr     string
	port     uint32
	priority int
}

// buildServers converts raw server sources into Server values, defaulting the
// port to 53 and ordering them by ascending NetworkManager DnsPriority (stable,
// so equal-priority servers keep discovery order).
func buildServers(sources []serverSource) []Server {
	servers := make([]Server, 0, len(sources))
	for _, source := range sources {
		port := source.port
		if port == 0 {
			port = 53
		}
		servers = append(servers, Server{
			Addr:     net.JoinHostPort(source.addr, strconv.FormatUint(uint64(port), 10)),
			Priority: source.priority,
		})
	}
	sort.SliceStable(servers, func(i, j int) bool {
		return servers[i].Priority < servers[j].Priority
	})
	return servers
}

// pollingProvider is a Provider backed by a fetch function polled on an
// interval. The snapshot is cached so Servers never blocks on the source.
type pollingProvider struct {
	mu      sync.RWMutex
	servers []Server
	fetch   func() ([]Server, error)
}

// newPollingProvider builds a pollingProvider with the given fetch function.
func newPollingProvider(fetch func() ([]Server, error)) *pollingProvider {
	return &pollingProvider{fetch: fetch}
}

// Servers returns a copy of the current snapshot.
func (providerInstance *pollingProvider) Servers() []Server {
	providerInstance.mu.RLock()
	defer providerInstance.mu.RUnlock()
	return append([]Server(nil), providerInstance.servers...)
}

// refreshOnce calls fetch and stores the result on success.
func (providerInstance *pollingProvider) refreshOnce() error {
	servers, err := providerInstance.fetch()
	if err != nil {
		return err
	}
	providerInstance.mu.Lock()
	providerInstance.servers = servers
	providerInstance.mu.Unlock()
	return nil
}

// Refresh performs a synchronous refresh and returns the freshly fetched
// servers. Useful for one-shot queries that need an up-to-date snapshot before
// resolving.
func (providerInstance *pollingProvider) Refresh() ([]Server, error) {
	if err := providerInstance.refreshOnce(); err != nil {
		return nil, err
	}
	return providerInstance.Servers(), nil
}

// Start performs an initial refresh in the background and then polls every
// interval until ctx is done. An interval <= 0 runs the initial refresh only.
// Failures are logged and leave the previous snapshot intact, so a transient
// D-Bus/NetworkManager outage never breaks resolution.
func (providerInstance *pollingProvider) Start(ctx context.Context, interval int) {
	go func() {
		if err := providerInstance.refreshOnce(); err != nil {
			log.Printf("dnsmc vpndns: initial refresh: %v", err)
		}
		if interval <= 0 {
			return
		}
		ticker := time.NewTicker(time.Duration(interval) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := providerInstance.refreshOnce(); err != nil {
					log.Printf("dnsmc vpndns: refresh: %v", err)
				}
			}
		}
	}()
}
