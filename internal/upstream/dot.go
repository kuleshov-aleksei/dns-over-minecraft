package upstream

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/miekg/dns"
)

type DoT struct {
	name      string
	address   string
	sni       string
	priority  int
	timeout   time.Duration
	tlsConfig *tls.Config
	pool      *connPool
}

func NewDoT(name string, address string, sni string, priority int, timeout time.Duration) *DoT {
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	dotUpstream := &DoT{
		name:      name,
		address:   address,
		sni:       sni,
		priority:  priority,
		timeout:   timeout,
		tlsConfig: &tls.Config{ServerName: sni, MinVersion: tls.VersionTLS12},
	}
	dotUpstream.pool = newConnPool(defaultConnPoolSize, func(requestContext context.Context) (*dns.Conn, error) {
		networkConnection, err := (&net.Dialer{KeepAlive: 30 * time.Second}).DialContext(requestContext, "tcp", dotUpstream.address)
		if err != nil {
			return nil, err
		}
		tlsConnection := tls.Client(networkConnection, dotUpstream.tlsConfig)
		handshakeDeadline := time.Now().Add(dotUpstream.timeout)
		if contextDeadline, exists := requestContext.Deadline(); exists && contextDeadline.Before(handshakeDeadline) {
			handshakeDeadline = contextDeadline
		}
		_ = tlsConnection.SetDeadline(handshakeDeadline)
		if err := tlsConnection.HandshakeContext(requestContext); err != nil {
			_ = networkConnection.Close()
			return nil, err
		}
		_ = tlsConnection.SetDeadline(time.Time{})
		return &dns.Conn{Conn: tlsConnection}, nil
	})
	return dotUpstream
}

func (dotUpstream *DoT) Name() string  { return dotUpstream.name }
func (dotUpstream *DoT) Priority() int { return dotUpstream.priority }

func (dotUpstream *DoT) Exchange(requestContext context.Context, queryMessage *dns.Msg) (*dns.Msg, error) {
	connection, reused, err := dotUpstream.pool.acquire(requestContext)
	if err != nil {
		return nil, err
	}
	responseMessage, exchangeErr := exchangeOnConn(requestContext, connection, queryMessage, dotUpstream.timeout)
	if exchangeErr == nil {
		dotUpstream.pool.release(connection, true)
		return responseMessage, nil
	}
	dotUpstream.pool.release(connection, false)
	if !reused {
		return nil, exchangeErr
	}
	// The pooled connection may have been silently closed by the upstream
	// (e.g. an idle timeout); retry once on a freshly dialed connection.
	freshConnection, dialErr := dotUpstream.pool.dialFresh(requestContext)
	if dialErr != nil {
		return nil, exchangeErr
	}
	responseMessage, exchangeErr = exchangeOnConn(requestContext, freshConnection, queryMessage, dotUpstream.timeout)
	_ = freshConnection.Close()
	return responseMessage, exchangeErr
}