package upstream

import (
	"context"
	"crypto/tls"
	"time"

	"github.com/miekg/dns"
)

type DoT struct {
	name     string
	address  string
	sni      string
	priority int
	timeout  time.Duration
}

func NewDoT(name string, address string, sni string, priority int, timeout time.Duration) *DoT {
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	return &DoT{name: name, address: address, sni: sni, priority: priority, timeout: timeout}
}

func (dotUpstream *DoT) Name() string  { return dotUpstream.name }
func (dotUpstream *DoT) Priority() int { return dotUpstream.priority }

func (dotUpstream *DoT) Exchange(requestContext context.Context, queryMessage *dns.Msg) (*dns.Msg, error) {
	dnsClient := &dns.Client{
		Net:     "tcp-tls",
		Timeout: dotUpstream.timeout,
		TLSConfig: &tls.Config{
			ServerName: dotUpstream.sni,
			MinVersion: tls.VersionTLS12,
		},
	}
	if deadline, exists := requestContext.Deadline(); exists {
		remainingDuration := time.Until(deadline)
		if remainingDuration < dotUpstream.timeout && remainingDuration > 0 {
			dnsClient.Timeout = remainingDuration
		}
	}
	responseMessage, _, err := dnsClient.ExchangeContext(requestContext, queryMessage, dotUpstream.address)
	return responseMessage, err
}
