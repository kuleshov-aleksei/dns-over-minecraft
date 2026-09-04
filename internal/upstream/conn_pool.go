package upstream

import (
	"context"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	// defaultConnPoolSize is the number of connections kept per TCP/DoT
	// upstream. Bounded so a single upstream cannot exhaust file descriptors.
	defaultConnPoolSize = 4
	// idleConnTimeout is how long a pooled connection may sit idle before it is
	// discarded instead of reused; upstreams commonly close idle TCP/TLS
	// connections.
	idleConnTimeout = 30 * time.Second
)

type pooledConn struct {
	conn     *dns.Conn
	lastUsed time.Time
}

// connPool is a small, bounded pool of live DNS connections for one upstream.
// Connections are shared across queries; a connection whose exchange fails is
// closed and dropped rather than reused, because its stream position is unknown.
type connPool struct {
	idle  chan *pooledConn
	dial  func(context.Context) (*dns.Conn, error)
	mutex sync.Mutex
	total int
	max   int
}

func newConnPool(max int, dial func(context.Context) (*dns.Conn, error)) *connPool {
	if max <= 0 {
		max = defaultConnPoolSize
	}
	return &connPool{
		idle: make(chan *pooledConn, max),
		dial: dial,
		max:  max,
	}
}

// acquire returns a connection for one exchange. The boolean reports whether
// the connection was reused from the pool (true) or freshly dialed (false), so
// callers can decide whether a failure warrants a retry on a fresh connection.
// Dialing and waiting respect the request context.
func (poolInstance *connPool) acquire(requestContext context.Context) (*dns.Conn, bool, error) {
	for {
		select {
		case pooled := <-poolInstance.idle:
			if time.Since(pooled.lastUsed) > idleConnTimeout {
				pooled.conn.Close()
				poolInstance.mutex.Lock()
				poolInstance.total--
				poolInstance.mutex.Unlock()
				continue
			}
			return pooled.conn, true, nil
		default:
		}

		poolInstance.mutex.Lock()
		if poolInstance.total < poolInstance.max {
			poolInstance.total++
			poolInstance.mutex.Unlock()
			connection, err := poolInstance.dial(requestContext)
			if err != nil {
				poolInstance.mutex.Lock()
				poolInstance.total--
				poolInstance.mutex.Unlock()
				return nil, false, err
			}
			return connection, false, nil
		}
		poolInstance.mutex.Unlock()
		break
	}

	select {
	case pooled := <-poolInstance.idle:
		return pooled.conn, true, nil
	case <-requestContext.Done():
		return nil, false, requestContext.Err()
	}
}

// release returns a connection to the pool. Unhealthy connections (failed
// exchanges) are closed and dropped so they are never reused.
func (poolInstance *connPool) release(connection *dns.Conn, healthy bool) {
	if !healthy {
		connection.Close()
		poolInstance.mutex.Lock()
		poolInstance.total--
		poolInstance.mutex.Unlock()
		return
	}
	pooled := &pooledConn{conn: connection, lastUsed: time.Now()}
	select {
	case poolInstance.idle <- pooled:
	default:
		connection.Close()
		poolInstance.mutex.Lock()
		poolInstance.total--
		poolInstance.mutex.Unlock()
	}
}

// dialFresh opens a brand-new connection outside the pool accounting. It is
// used to retry an exchange once after a pooled connection was found stale.
func (poolInstance *connPool) dialFresh(requestContext context.Context) (*dns.Conn, error) {
	return poolInstance.dial(requestContext)
}

// exchangeOnConn performs a single DNS exchange over an existing connection,
// bounded by the shorter of the upstream timeout and the request context
// deadline, and validated against the query (ID + question). It never closes
// the connection; callers decide reuse based on the returned error.
func exchangeOnConn(requestContext context.Context, connection *dns.Conn, queryMessage *dns.Msg, timeout time.Duration) (*dns.Msg, error) {
	deadline := time.Now().Add(timeout)
	if requestDeadline, exists := requestContext.Deadline(); exists && requestDeadline.Before(deadline) {
		deadline = requestDeadline
	}
	_ = connection.SetWriteDeadline(deadline)
	if err := connection.WriteMsg(queryMessage); err != nil {
		return nil, err
	}
	_ = connection.SetReadDeadline(deadline)
	responseMessage, err := connection.ReadMsg()
	if err != nil {
		return nil, err
	}
	if err := validateResponse(responseMessage, queryMessage); err != nil {
		return nil, err
	}
	return responseMessage, nil
}