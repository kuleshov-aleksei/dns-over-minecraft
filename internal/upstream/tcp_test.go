package upstream

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// serveDNSConn answers DNS messages on a raw connection until it fails.
func serveDNSConn(connection net.Conn) {
	defer connection.Close()
	dnsConn := &dns.Conn{Conn: connection}
	for {
		queryMessage, err := dnsConn.ReadMsg()
		if err != nil {
			return
		}
		responseMessage := new(dns.Msg)
		responseMessage.SetReply(queryMessage)
		if err := dnsConn.WriteMsg(responseMessage); err != nil {
			return
		}
	}
}

// acceptLoop accepts connections on a listener and serves each one, recording
// the accepted count on the channel.
func acceptLoop(listener net.Listener, accepted chan struct{}) {
	for {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		accepted <- struct{}{}
		go serveDNSConn(connection)
	}
}

func TestTCP_ExchangeReusesConnection(testingInstance *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		testingInstance.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	accepted := make(chan struct{}, 16)
	go acceptLoop(listener, accepted)

	tcpUpstream := NewTCP("tcp-test", listener.Addr().String(), 10, time.Second)
	queryMessage := makeMessage(testingInstance, "example.com")
	for index := 0; index < 5; index++ {
		responseMessage, err := tcpUpstream.Exchange(context.Background(), queryMessage)
		if err != nil {
			testingInstance.Fatalf("exchange %d: %v", index, err)
		}
		if responseMessage == nil || responseMessage.Rcode != dns.RcodeSuccess {
			testingInstance.Fatalf("exchange %d: bad response", index)
		}
	}
	if count := len(accepted); count != 1 {
		testingInstance.Fatalf("want 1 accepted conn for 5 sequential exchanges, got %d", count)
	}
}

func TestTCP_RetriesOnceAfterStaleConnection(testingInstance *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		testingInstance.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	var acceptedCount int32
	go func() {
		// First connection answers one query then closes immediately, so the
		// second exchange must redial and be served by a fresh connection.
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		atomic.AddInt32(&acceptedCount, 1)
		dnsConn := &dns.Conn{Conn: connection}
		queryMessage, readErr := dnsConn.ReadMsg()
		if readErr != nil {
			return
		}
		responseMessage := new(dns.Msg)
		responseMessage.SetReply(queryMessage)
		_ = dnsConn.WriteMsg(responseMessage)
		_ = connection.Close()

		connectionSecond, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		atomic.AddInt32(&acceptedCount, 1)
		serveDNSConn(connectionSecond)
	}()

	tcpUpstream := NewTCP("tcp-stale", listener.Addr().String(), 10, time.Second)
	queryMessage := makeMessage(testingInstance, "example.com")
	if _, err := tcpUpstream.Exchange(context.Background(), queryMessage); err != nil {
		testingInstance.Fatalf("first exchange: %v", err)
	}
	if _, err := tcpUpstream.Exchange(context.Background(), queryMessage); err != nil {
		testingInstance.Fatalf("exchange over stale conn should retry and succeed: %v", err)
	}
	if atomic.LoadInt32(&acceptedCount) != 2 {
		testingInstance.Fatalf("want 2 accepted conns (initial + retry), got %d", atomic.LoadInt32(&acceptedCount))
	}
}