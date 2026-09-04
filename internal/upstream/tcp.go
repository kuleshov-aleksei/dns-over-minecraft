package upstream

import (
	"context"
	"net"
	"time"

	"github.com/miekg/dns"
)

type TCP struct {
	name     string
	address  string
	priority int
	timeout  time.Duration
	pool     *connPool
}

func NewTCP(name string, address string, priority int, timeout time.Duration) *TCP {
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	tcpUpstream := &TCP{name: name, address: address, priority: priority, timeout: timeout}
	tcpUpstream.pool = newConnPool(defaultConnPoolSize, func(requestContext context.Context) (*dns.Conn, error) {
		networkConnection, err := (&net.Dialer{KeepAlive: 30 * time.Second}).DialContext(requestContext, "tcp", tcpUpstream.address)
		if err != nil {
			return nil, err
		}
		return &dns.Conn{Conn: networkConnection}, nil
	})
	return tcpUpstream
}

func (tcpUpstream *TCP) Name() string     { return tcpUpstream.name }
func (tcpUpstream *TCP) Priority() int    { return tcpUpstream.priority }
func (tcpUpstream *TCP) Exchange(requestContext context.Context, queryMessage *dns.Msg) (*dns.Msg, error) {
	connection, reused, err := tcpUpstream.pool.acquire(requestContext)
	if err != nil {
		return nil, err
	}
	responseMessage, exchangeErr := exchangeOnConn(requestContext, connection, queryMessage, tcpUpstream.timeout)
	if exchangeErr == nil {
		tcpUpstream.pool.release(connection, true)
		return responseMessage, nil
	}
	tcpUpstream.pool.release(connection, false)
	if !reused {
		return nil, exchangeErr
	}
	// The pooled connection may have been silently closed by the upstream
	// (e.g. an idle timeout); retry once on a freshly dialed connection.
	freshConnection, dialErr := tcpUpstream.pool.dialFresh(requestContext)
	if dialErr != nil {
		return nil, exchangeErr
	}
	responseMessage, exchangeErr = exchangeOnConn(requestContext, freshConnection, queryMessage, tcpUpstream.timeout)
	_ = freshConnection.Close()
	return responseMessage, exchangeErr
}