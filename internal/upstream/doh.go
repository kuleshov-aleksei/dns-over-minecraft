package upstream

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"time"

	"github.com/miekg/dns"
)

type DoH struct {
	name     string
	url      string
	priority int
	timeout  time.Duration
	client   *http.Client
}

func NewDoH(name, url string, priority int, timeout time.Duration) *DoH {
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	return &DoH{
		name:     name,
		url:      url,
		priority: priority,
		timeout:  timeout,
		client:   &http.Client{Timeout: timeout},
	}
}

func (d *DoH) Name() string  { return d.name }
func (d *DoH) Priority() int { return d.priority }

func (d *DoH) Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	wire, err := msg.Pack()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", d.url, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	// also apply timeout from context
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining < d.timeout && remaining > 0 {
			d.client.Timeout = remaining
		}
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, io.ErrUnexpectedEOF
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, err
	}
	out := new(dns.Msg)
	if err := out.Unpack(body); err != nil {
		return nil, err
	}
	return out, nil
}
