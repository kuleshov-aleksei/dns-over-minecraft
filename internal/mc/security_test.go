package mc

import (
	"bytes"
	"net"
	"strings"
	"testing"

	"github.com/dns-over-minecraft/dns-over-minecraft/internal/dnscodec"
	"github.com/dns-over-minecraft/dns-over-minecraft/internal/records"
	"github.com/dns-over-minecraft/dns-over-minecraft/internal/resolver"
	"github.com/miekg/dns"
)

// startSecurityTestServer builds a Server with the given hardening knobs and
// serves it in the same way startTestServer does (handleConn per accept).
func startSecurityTestServer(t *testing.T, passphrase string, rateLimit int) (string, *Server) {
	t.Helper()
	recordStore, err := records.New([]records.Record{
		{Name: "*.example.com", Type: "A", TTL: 60, Values: []string{"10.0.0.9"}},
	})
	if err != nil {
		t.Fatalf("records.New: %v", err)
	}
	serverInstance := &Server{
		Suffix:     ".mc",
		MOTD:       "§aDNS over Minecraft §7| test",
		Resolver:   resolver.New(nil, recordStore, nil),
		Passphrase: passphrase,
		RateLimit:  rateLimit,
		fragments:  newFragmentAssembler(),
	}
	if rateLimit > 0 {
		serverInstance.rateLimiter = newIPRateLimiter(rateLimit)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
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
	t.Cleanup(func() { _ = listener.Close() })
	return listener.Addr().String(), serverInstance
}

func securityQuery(t *testing.T, name string, queryType uint16) *dns.Msg {
	t.Helper()
	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn(name), queryType)
	message.RecursionDesired = true
	return message
}

func TestExtractPassphrase(t *testing.T) {
	remainder, ok := extractPassphrase("p.s3cr3t.m5xw6z3mmuxgg33n", "s3cr3t")
	if !ok || remainder != "m5xw6z3mmuxgg33n" {
		t.Fatalf("extractPassphrase got (%q, %v), want (%q, true)", remainder, ok, "m5xw6z3mmuxgg33n")
	}
	if _, ok := extractPassphrase("m5xw6z3mmuxgg33n", "s3cr3t"); ok {
		t.Fatalf("extractPassphrase should reject address without marker")
	}
	if _, ok := extractPassphrase("p.wrong.m5xw6z3mmuxgg33n", "s3cr3t"); ok {
		t.Fatalf("extractPassphrase should reject wrong passphrase")
	}
	if _, ok := extractPassphrase("p.s3cr3t", "s3cr3t"); ok {
		t.Fatalf("extractPassphrase should reject passphrase-only address")
	}
	if remainder, ok := extractPassphrase("p.abcdef.n.1234.piece.mc", "abcdef"); !ok || remainder != "n.1234.piece.mc" {
		t.Fatalf("fragment remainder = (%q, %v), want (n.1234.piece.mc, true)", remainder, ok)
	}
}

func TestServer_PassphraseRequired(t *testing.T) {
	serverAddress, _ := startSecurityTestServer(t, "s3cr3t", 0)
	queryMessage := securityQuery(t, "example.com", dns.TypeA)

	response, err := Query(serverAddress, ".mc", "s3cr3t", queryMessage)
	if err != nil {
		t.Fatalf("authenticated query should succeed: %v", err)
	}
	answer, ok := response.Answer[0].(*dns.A)
	if !ok || answer.A.String() != "10.0.0.9" {
		t.Fatalf("unexpected answer: %v", response.Answer)
	}

	if _, err := Query(serverAddress, ".mc", "", queryMessage); err == nil {
		t.Fatalf("query without passphrase should be rejected")
	}
	if _, err := Query(serverAddress, ".mc", "wrong", queryMessage); err == nil {
		t.Fatalf("query with wrong passphrase should be rejected")
	}
}

func TestServer_NoPassphraseOpenWhenUnset(t *testing.T) {
	serverAddress, _ := startSecurityTestServer(t, "", 0)
	queryMessage := securityQuery(t, "example.com", dns.TypeA)

	response, err := Query(serverAddress, ".mc", "", queryMessage)
	if err != nil {
		t.Fatalf("query without passphrase should work when ACL unset: %v", err)
	}
	if len(response.Answer) != 1 {
		t.Fatalf("want 1 answer, got %d", len(response.Answer))
	}
}

func TestServer_RateLimit(t *testing.T) {
	serverAddress, _ := startSecurityTestServer(t, "", 1)
	queryMessage := securityQuery(t, "example.com", dns.TypeA)

	if _, err := Query(serverAddress, ".mc", "", queryMessage); err != nil {
		t.Fatalf("first query should be allowed: %v", err)
	}
	if _, err := Query(serverAddress, ".mc", "", queryMessage); err == nil {
		t.Fatalf("second query within budget should be rate-limited")
	}
}

func TestReadFrameLimit_RejectsOversizedFrame(t *testing.T) {
	frameBytes := WriteFrame(0x00, bytes.Repeat([]byte{0x41}, 16))
	if _, _, err := ReadFrameLimit(bytes.NewReader(frameBytes), 8); err == nil {
		t.Fatalf("ReadFrameLimit should reject a frame over its limit")
	}
	_, payload, err := ReadFrame(bytes.NewReader(frameBytes))
	if err != nil {
		t.Fatalf("ReadFrame should accept a 16-byte frame: %v", err)
	}
	if len(payload) != 16 {
		t.Fatalf("payload length %d, want 16", len(payload))
	}
}

func TestAuthPrefixFor(t *testing.T) {
	if authPrefixFor("") != "" {
		t.Fatalf("empty passphrase should produce empty prefix")
	}
	if got := authPrefixFor("s3cr3t"); got != "p.s3cr3t." {
		t.Fatalf("authPrefixFor = %q, want p.s3cr3t.", got)
	}
}

// TestQuery_WithPassphraseBudget ensures the passphrase prefix is accounted for
// in the non-fragmented 255-byte address budget.
func TestQuery_WithPassphraseStaysUnder255(t *testing.T) {
	serverAddress, _ := startSecurityTestServer(t, "s3cr3t", 0)
	queryMessage := new(dns.Msg)
	queryMessage.SetQuestion(dns.Fqdn(strings.Repeat("a", 60)+".example.com"), dns.TypeA)
	queryMessage.RecursionDesired = true

	encodedQuery, err := dnscodec.EncodeQuery(queryMessage)
	if err != nil {
		t.Fatalf("EncodeQuery: %v", err)
	}
	fullAddress := "p.s3cr3t." + encodedQuery + ".mc"
	if len(fullAddress) > maxSingleServerAddress {
		t.Fatalf("authenticated address exceeds 255: %d", len(fullAddress))
	}

	response, err := Query(serverAddress, ".mc", "s3cr3t", queryMessage)
	if err != nil {
		t.Fatalf("authenticated query should succeed: %v", err)
	}
	if len(response.Answer) != 1 {
		t.Fatalf("want 1 answer, got %d", len(response.Answer))
	}
}
