package upstream

import (
	"context"
	"crypto/tls"
	"time"

	"github.com/miekg/dns"
)

type DoT struct {
	name     string
	addr     string
	sni      string
	priority int
	timeout  time.Duration
}

func NewDoT(name, addr, sni string, priority int, timeout time.Duration) *DoT {
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	return &DoT{name: name, addr: addr, sni: sni, priority: priority, timeout: timeout}
}

func (d *DoT) Name() string  { return d.name }
func (d *DoT) Priority() int { return d.priority }

func (d *DoT) Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	c := &dns.Client{
		Net:     "tcp-tls",
		Timeout: d.timeout,
		TLSConfig: &tls.Config{
			ServerName: d.sni,
			MinVersion: tls.VersionTLS12,
		},
	}
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining < d.timeout && remaining > 0 {
			c.Timeout = remaining
		}
	}
	resp, _, err := c.ExchangeContext(ctx, msg, d.addr)
	return resp, err
}
