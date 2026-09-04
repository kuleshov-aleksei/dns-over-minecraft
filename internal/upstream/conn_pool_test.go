package upstream

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func testDialFunc(dialCount *int, dialMutex *sync.Mutex) func(context.Context) (*dns.Conn, error) {
	return func(_ context.Context) (*dns.Conn, error) {
		if dialMutex != nil {
			dialMutex.Lock()
			*dialCount++
			dialMutex.Unlock()
		}
		clientSide, _ := net.Pipe()
		return &dns.Conn{Conn: clientSide}, nil
	}
}

func TestConnPool_ReusesConnections(testingInstance *testing.T) {
	var dialCount int
	var dialMutex sync.Mutex
	pool := newConnPool(2, testDialFunc(&dialCount, &dialMutex))
	requestContext := context.Background()

	firstConn, reused, err := pool.acquire(requestContext)
	if err != nil {
		testingInstance.Fatalf("first acquire: %v", err)
	}
	if reused {
		testingInstance.Fatalf("first acquire should be fresh")
	}
	pool.release(firstConn, true)

	secondConn, reused, err := pool.acquire(requestContext)
	if err != nil {
		testingInstance.Fatalf("second acquire: %v", err)
	}
	if !reused {
		testingInstance.Fatalf("second acquire should reuse the pooled connection")
	}
	pool.release(secondConn, true)

	if dialCount != 1 {
		testingInstance.Fatalf("want 1 dial across acquire/release/acquire, got %d", dialCount)
	}
}

func TestConnPool_BlocksWhenFull(testingInstance *testing.T) {
	var dialCount int
	pool := newConnPool(1, testDialFunc(&dialCount, nil))
	requestContext := context.Background()

	heldConn, _, err := pool.acquire(requestContext)
	if err != nil {
		testingInstance.Fatalf("acquire: %v", err)
	}

	timeoutContext, cancelFunc := context.WithTimeout(requestContext, 50*time.Millisecond)
	defer cancelFunc()
	_, _, err = pool.acquire(timeoutContext)
	if !errors.Is(err, context.DeadlineExceeded) {
		testingInstance.Fatalf("want deadline exceeded while pool full, got %v", err)
	}
	pool.release(heldConn, true)
}

func TestConnPool_UnhealthyConnDropped(testingInstance *testing.T) {
	var dialCount int
	var dialMutex sync.Mutex
	pool := newConnPool(2, testDialFunc(&dialCount, &dialMutex))
	requestContext := context.Background()

	conn, _, err := pool.acquire(requestContext)
	if err != nil {
		testingInstance.Fatalf("acquire: %v", err)
	}
	pool.release(conn, false)

	nextConn, reused, err := pool.acquire(requestContext)
	if err != nil {
		testingInstance.Fatalf("re-acquire: %v", err)
	}
	if reused {
		testingInstance.Fatalf("unhealthy connection must not be reused")
	}
	if dialCount != 2 {
		testingInstance.Fatalf("want 2 dials after unhealthy release, got %d", dialCount)
	}
	pool.release(nextConn, true)
}

func TestConnPool_StaleIdleConnDiscarded(testingInstance *testing.T) {
	var dialCount int
	var dialMutex sync.Mutex
	pool := newConnPool(2, testDialFunc(&dialCount, &dialMutex))
	requestContext := context.Background()

	conn, _, err := pool.acquire(requestContext)
	if err != nil {
		testingInstance.Fatalf("acquire: %v", err)
	}
	pool.release(conn, true)

	// Backdate the idle connection past the idle timeout.
	pooled := <-pool.idle
	pooled.lastUsed = time.Now().Add(-idleConnTimeout - time.Second)
	pool.idle <- pooled

	nextConn, reused, err := pool.acquire(requestContext)
	if err != nil {
		testingInstance.Fatalf("re-acquire: %v", err)
	}
	if reused {
		testingInstance.Fatalf("stale idle connection should be discarded")
	}
	if dialCount != 2 {
		testingInstance.Fatalf("want 2 dials after stale idle conn, got %d", dialCount)
	}
	pool.release(nextConn, true)
}

func TestConnPool_DialFailureDecrements(testingInstance *testing.T) {
	failingDial := func(_ context.Context) (*dns.Conn, error) {
		return nil, errors.New("dial refused")
	}
	pool := newConnPool(2, failingDial)
	requestContext := context.Background()

	_, _, err := pool.acquire(requestContext)
	if err == nil {
		testingInstance.Fatalf("want dial error")
	}

	// The failed dial must not leave a leaked slot: a later dial should still
	// be attempted rather than blocking forever.
	var dialCount int
	pool.dial = func(_ context.Context) (*dns.Conn, error) {
		dialCount++
		clientSide, _ := net.Pipe()
		return &dns.Conn{Conn: clientSide}, nil
	}
	conn, _, err := pool.acquire(requestContext)
	if err != nil {
		testingInstance.Fatalf("acquire after failed dial: %v", err)
	}
	if dialCount != 1 {
		testingInstance.Fatalf("want 1 dial after failed dial, got %d", dialCount)
	}
	pool.release(conn, true)
}