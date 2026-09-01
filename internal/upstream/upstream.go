package upstream

import (
	"context"
	"sort"

	"github.com/miekg/dns"
)

type Upstream interface {
	Name() string
	Priority() int
	Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error)
}

type Pool struct {
	upstreams []Upstream
}

func NewPool(ups []Upstream) *Pool {
	sort.Slice(ups, func(i, j int) bool {
		if ups[i].Priority() == ups[j].Priority() {
			return ups[i].Name() < ups[j].Name()
		}
		return ups[i].Priority() < ups[j].Priority()
	})
	return &Pool{upstreams: ups}
}

func (p *Pool) Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	var lastErr error
	for _, u := range p.upstreams {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		resp, err := u.Exchange(ctx, msg)
		if err == nil && resp != nil {
			return resp, nil
		}
		if err != nil {
			lastErr = err
		} else {
			lastErr = nil
		}
		// try next priority
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, context.DeadlineExceeded
}

func (p *Pool) List() []Upstream { return p.upstreams }
