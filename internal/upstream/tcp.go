package upstream

import (
	"context"
	"time"

	"github.com/miekg/dns"
)

type TCP struct {
	name     string
	address  string
	priority int
	timeout  time.Duration
}

func NewTCP(name string, address string, priority int, timeout time.Duration) *TCP {
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	return &TCP{name: name, address: address, priority: priority, timeout: timeout}
}

func (tcpUpstream *TCP) Name() string     { return tcpUpstream.name }
func (tcpUpstream *TCP) Priority() int    { return tcpUpstream.priority }
func (tcpUpstream *TCP) Exchange(requestContext context.Context, queryMessage *dns.Msg) (*dns.Msg, error) {
	dnsClient := &dns.Client{Net: "tcp", Timeout: tcpUpstream.timeout}
	if deadline, exists := requestContext.Deadline(); exists {
		remainingDuration := time.Until(deadline)
		if remainingDuration < tcpUpstream.timeout && remainingDuration > 0 {
			dnsClient.Timeout = remainingDuration
		}
	}
	responseMessage, _, err := dnsClient.ExchangeContext(requestContext, queryMessage, tcpUpstream.address)
	return responseMessage, err
}
