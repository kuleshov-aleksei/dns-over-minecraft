package upstream

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func newDoHTestServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server
}

func dohQuery(t *testing.T, name string, queryType uint16) *dns.Msg {
	t.Helper()
	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn(name), queryType)
	message.RecursionDesired = true
	message.Id = 1
	return message
}

func dohResponseHandler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(responseWriter http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(responseWriter, "bad content type", http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			http.Error(responseWriter, "read body", http.StatusBadRequest)
			return
		}
		queryMessage := new(dns.Msg)
		if err := queryMessage.Unpack(body); err != nil {
			http.Error(responseWriter, "unpack", http.StatusBadRequest)
			return
		}
		responseMessage := new(dns.Msg)
		responseMessage.SetReply(queryMessage)
		responseMessage.Rcode = dns.RcodeSuccess
		responseWire, err := responseMessage.Pack()
		if err != nil {
			http.Error(responseWriter, "pack", http.StatusBadRequest)
			return
		}
		responseWriter.Header().Set("Content-Type", "application/dns-message")
		_, _ = responseWriter.Write(responseWire)
	}
}

func TestDoH_Exchange(t *testing.T) {
	testServer := newDoHTestServer(t, dohResponseHandler(t))
	dohUpstream := NewDoH("test-doh", testServer.URL, 10, 2*time.Second)
	queryMessage := dohQuery(t, "example.com", dns.TypeA)

	responseMessage, err := dohUpstream.Exchange(context.Background(), queryMessage)
	if err != nil {
		t.Fatalf("exchange err: %v", err)
	}
	if responseMessage == nil || responseMessage.Rcode != dns.RcodeSuccess {
		t.Fatalf("want NOERROR response, got %v", responseMessage)
	}
	if len(responseMessage.Question) != 1 || responseMessage.Question[0].Name != "example.com." {
		t.Fatalf("question not preserved: %v", responseMessage.Question)
	}
}

func TestDoH_ConcurrentExchanges(t *testing.T) {
	testServer := newDoHTestServer(t, dohResponseHandler(t))
	dohUpstream := NewDoH("test-doh", testServer.URL, 10, 2*time.Second)
	queryMessage := dohQuery(t, "concurrent.example.com", dns.TypeA)

	const goroutineCount = 50
	var waitGroup sync.WaitGroup
	errorChannel := make(chan error, goroutineCount)
	for index := 0; index < goroutineCount; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			if _, err := dohUpstream.Exchange(context.Background(), queryMessage); err != nil {
				errorChannel <- err
			}
		}()
	}
	waitGroup.Wait()
	close(errorChannel)
	for err := range errorChannel {
		t.Fatalf("concurrent exchange err: %v", err)
	}
}

func TestDoH_Timeout(t *testing.T) {
	slowHandler := func(responseWriter http.ResponseWriter, request *http.Request) {
		time.Sleep(300 * time.Millisecond)
		responseWriter.WriteHeader(http.StatusOK)
	}
	testServer := newDoHTestServer(t, slowHandler)
	dohUpstream := NewDoH("slow-doh", testServer.URL, 10, 50*time.Millisecond)
	queryMessage := dohQuery(t, "slow.example.com", dns.TypeA)

	_, err := dohUpstream.Exchange(context.Background(), queryMessage)
	if err == nil {
		t.Fatalf("want timeout error, got nil")
	}
}

func TestDoH_ContextDeadlineHonored(t *testing.T) {
	slowHandler := func(responseWriter http.ResponseWriter, request *http.Request) {
		time.Sleep(300 * time.Millisecond)
		responseWriter.WriteHeader(http.StatusOK)
	}
	testServer := newDoHTestServer(t, slowHandler)
	dohUpstream := NewDoH("slow-doh", testServer.URL, 10, 2*time.Second)
	queryMessage := dohQuery(t, "deadline.example.com", dns.TypeA)

	requestContext, cancelFunc := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancelFunc()
	_, err := dohUpstream.Exchange(requestContext, queryMessage)
	if err == nil {
		t.Fatalf("want deadline error, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Fatalf("want context deadline exceeded, got %v", err)
	}
}
