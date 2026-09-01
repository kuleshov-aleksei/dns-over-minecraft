package upstream

import (
	"context"
	"time"

	"github.com/miekg/dns"
)

type TCP struct {
	name     string
	addr     string
	priority int
	timeout  time.Duration
}

func NewTCP(name, addr string, priority int, timeout time.Duration) *TCP {
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	return &TCP{name: name, addr: addr, priority: priority, timeout: timeout}
}

func (t *TCP) Name() string     { return t.name }
func (t *TCP) Priority() int    { return t.priority }
func (t *TCP) Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	c := &dns.Client{Net: "tcp", Timeout: t.timeout}
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining < t.timeout && remaining > 0 {
			c.Timeout = remaining
		}
	}
	resp, _, err := c.ExchangeContext(ctx, msg, t.addr)
	return resp, err
}
