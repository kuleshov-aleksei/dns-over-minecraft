package mc

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/dns-over-minecraft/dns-over-minecraft/internal/dnscodec"
	"github.com/dns-over-minecraft/dns-over-minecraft/internal/records"
	"github.com/dns-over-minecraft/dns-over-minecraft/internal/resolver"
	"github.com/miekg/dns"
)

func TestFragmentAssembler_CompletesInOrder(testedInstance *testing.T) {
	assembler := newFragmentAssembler()
	key := fragmentKey{clientIP: "1.2.3.4", nonce: "abcd"}

	set, completer := assembler.add(key, 1, 2, "part1")
	if completer {
		testedInstance.Fatal("first piece must not complete the set")
	}
	_, completer = assembler.add(key, 2, 2, "part2")
	if !completer {
		testedInstance.Fatal("last piece should complete the set")
	}
	if reassembled := set.reassemble(); reassembled != "part1part2" {
		testedInstance.Fatalf("reassemble %q, want %q", reassembled, "part1part2")
	}

	response := &dns.Msg{}
	set.storeResult(response, nil)
	gotResponse, err := set.waitResult()
	if err != nil {
		testedInstance.Fatalf("waitResult err: %v", err)
	}
	if gotResponse != response {
		testedInstance.Fatal("waitResult did not return stored response")
	}
}

func TestFragmentAssembler_CompletesOutOfOrder(testedInstance *testing.T) {
	assembler := newFragmentAssembler()
	key := fragmentKey{clientIP: "1.2.3.4", nonce: "wxyz"}

	assembler.add(key, 3, 3, "C")
	assembler.add(key, 1, 3, "A")
	set, completer := assembler.add(key, 2, 3, "B")
	if !completer {
		testedInstance.Fatal("adding last missing piece should complete")
	}
	if reassembled := set.reassemble(); reassembled != "ABC" {
		testedInstance.Fatalf("reassemble %q, want %q", reassembled, "ABC")
	}
}

func TestFragmentAssembler_WaitForCompleter(testedInstance *testing.T) {
	assembler := newFragmentAssembler()
	key := fragmentKey{clientIP: "1.2.3.4", nonce: "efgh"}
	set, _ := assembler.add(key, 1, 2, "A")

	resultChannel := make(chan *dns.Msg, 1)
	errorChannel := make(chan error, 1)
	go func() {
		response, err := set.waitResult()
		resultChannel <- response
		errorChannel <- err
	}()

	_, completer := assembler.add(key, 2, 2, "B")
	if !completer {
		testedInstance.Fatal("second piece should complete")
	}
	expectedResponse := &dns.Msg{MsgHdr: dns.MsgHdr{Id: 42}}
	set.storeResult(expectedResponse, nil)

	select {
	case <-time.After(2 * time.Second):
		testedInstance.Fatal("waitResult blocked, completer never signalled")
	case response := <-resultChannel:
		if err := <-errorChannel; err != nil {
			testedInstance.Fatalf("waitResult err: %v", err)
		}
		if response != expectedResponse {
			testedInstance.Fatal("waitResult returned wrong response")
		}
	}
}

func TestFragmentAssembler_WaitTimeout(testedInstance *testing.T) {
	originalTimeout := fragmentTimeout
	fragmentTimeout = 50 * time.Millisecond
	defer func() { fragmentTimeout = originalTimeout }()

	assembler := newFragmentAssembler()
	key := fragmentKey{clientIP: "1.2.3.4", nonce: "ijkl"}
	set, _ := assembler.add(key, 1, 2, "A")

	startTime := time.Now()
	_, err := set.waitResult()
	if err == nil {
		testedInstance.Fatal("waitResult should time out for an incomplete set")
	}
	if time.Since(startTime) > time.Second {
		testedInstance.Fatalf("timeout took too long: %s", time.Since(startTime))
	}
}

func TestFragmentAssembler_Expiry(testedInstance *testing.T) {
	assembler := newFragmentAssembler()
	oldKey := fragmentKey{clientIP: "9.9.9.9", nonce: "mnop"}
	assembler.add(oldKey, 1, 2, "x")

	assembler.mutex.Lock()
	assembler.sets[oldKey].lastSeen = time.Now().Add(-30 * time.Second)
	assembler.mutex.Unlock()

	assembler.add(fragmentKey{clientIP: "8.8.8.8", nonce: "qrst"}, 1, 2, "y")
	assembler.mutex.Lock()
	_, stillExists := assembler.sets[oldKey]
	assembler.mutex.Unlock()
	if stillExists {
		testedInstance.Fatal("expired fragment set should be purged")
	}
}

func TestSplitEncodedPieces(testedInstance *testing.T) {
	pieces := splitEncodedPieces("abcdefghij", 4)
	want := []string{"abcd", "efgh", "ij"}
	if len(pieces) != len(want) {
		testedInstance.Fatalf("pieces %v, want %v", pieces, want)
	}
	for index := range want {
		if pieces[index] != want[index] {
			testedInstance.Fatalf("piece %d = %q, want %q", index, pieces[index], want[index])
		}
	}
	if joined := strings.Join(splitEncodedPieces("abc", 10), ""); joined != "abc" {
		testedInstance.Fatalf("single piece join %q", joined)
	}
}

func TestChunkLabels(testedInstance *testing.T) {
	if chunked := chunkLabels("abcdef", 3); chunked != "abc.def" {
		testedInstance.Fatalf("chunkLabels %q", chunked)
	}
	if chunked := chunkLabels("abcd", 5); chunked != "abcd" {
		testedInstance.Fatalf("chunkLabels short %q", chunked)
	}
}

func startTestServer(testedInstance *testing.T) (string, *Server) {
	testedInstance.Helper()
	recordStore, err := records.New([]records.Record{
		{Name: "*.example.com", Type: "A", TTL: 60, Values: []string{"10.0.0.9"}},
	})
	if err != nil {
		testedInstance.Fatalf("records.New: %v", err)
	}
	serverInstance := &Server{
		Suffix:    ".mc",
		Resolver:  resolver.New(nil, recordStore, nil),
		fragments: newFragmentAssembler(),
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		testedInstance.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go serverInstance.handleConn(connection)
		}
	}()
	testedInstance.Cleanup(func() { _ = listener.Close() })
	return listener.Addr().String(), serverInstance
}

func TestQuery_FragmentedEndToEnd(testedInstance *testing.T) {
	serverAddress, _ := startTestServer(testedInstance)

	longName := strings.Repeat("a", 40) + "." + strings.Repeat("b", 40) + "." +
		strings.Repeat("c", 40) + "." + strings.Repeat("d", 40) + ".example.com"
	queryMessage := new(dns.Msg)
	queryMessage.SetQuestion(dns.Fqdn(longName), dns.TypeA)
	queryMessage.RecursionDesired = true

	encodedQuery, err := dnscodec.EncodeQuery(queryMessage)
	if err != nil {
		testedInstance.Fatalf("EncodeQuery: %v", err)
	}
	if len(encodedQuery) <= maxSingleServerAddress {
		testedInstance.Fatalf("test name must exceed 255 chars, got %d", len(encodedQuery))
	}

	response, err := Query(serverAddress, ".mc", queryMessage)
	if err != nil {
		testedInstance.Fatalf("fragmented query: %v", err)
	}
	if len(response.Answer) != 1 {
		testedInstance.Fatalf("want 1 answer, got %d", len(response.Answer))
	}
	answer, ok := response.Answer[0].(*dns.A)
	if !ok {
		testedInstance.Fatalf("answer not A record: %T", response.Answer[0])
	}
	if answer.A.String() != "10.0.0.9" {
		testedInstance.Fatalf("answer %s, want 10.0.0.9", answer.A.String())
	}
}

func TestQuery_SingleStillWorks(testedInstance *testing.T) {
	serverAddress, _ := startTestServer(testedInstance)

	queryMessage := new(dns.Msg)
	queryMessage.SetQuestion(dns.Fqdn("short.example.com"), dns.TypeA)
	queryMessage.RecursionDesired = true

	response, err := Query(serverAddress, ".mc", queryMessage)
	if err != nil {
		testedInstance.Fatalf("single query: %v", err)
	}
	answer, ok := response.Answer[0].(*dns.A)
	if !ok || answer.A.String() != "10.0.0.9" {
		testedInstance.Fatalf("unexpected answer: %v", response.Answer)
	}
}
