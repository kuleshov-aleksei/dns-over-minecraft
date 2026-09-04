package upstream

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// testTLSConfig returns a self-signed server certificate plus a client trust
// pool so the DoT client can validate the test server's identity.
func testTLSConfig(testingInstance *testing.T) (tls.Certificate, *x509.CertPool) {
	testingInstance.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		testingInstance.Fatalf("generate key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		testingInstance.Fatalf("create cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(derBytes)
	if err != nil {
		testingInstance.Fatalf("parse cert: %v", err)
	}
	trustPool := x509.NewCertPool()
	trustPool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{derBytes}, PrivateKey: privateKey}, trustPool
}

func TestDoT_ExchangeReusesConnection(testingInstance *testing.T) {
	certificate, trustPool := testTLSConfig(testingInstance)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}})
	if err != nil {
		testingInstance.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	accepted := make(chan struct{}, 16)
	go acceptLoop(listener, accepted)

	dotUpstream := NewDoT("dot-test", listener.Addr().String(), "localhost", 10, 2*time.Second)
	dotUpstream.tlsConfig.RootCAs = trustPool
	queryMessage := makeMessage(testingInstance, "example.com")
	for index := 0; index < 5; index++ {
		responseMessage, err := dotUpstream.Exchange(context.Background(), queryMessage)
		if err != nil {
			testingInstance.Fatalf("exchange %d: %v", index, err)
		}
		if responseMessage == nil || responseMessage.Rcode != dns.RcodeSuccess {
			testingInstance.Fatalf("exchange %d: bad response", index)
		}
	}
	if count := len(accepted); count != 1 {
		testingInstance.Fatalf("want 1 accepted TLS conn for 5 sequential exchanges, got %d", count)
	}
}