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

func NewDoH(name string, url string, priority int, timeout time.Duration) *DoH {
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

func (dohUpstream *DoH) Name() string  { return dohUpstream.name }
func (dohUpstream *DoH) Priority() int { return dohUpstream.priority }

func (dohUpstream *DoH) Exchange(requestContext context.Context, queryMessage *dns.Msg) (*dns.Msg, error) {
	wireBytes, err := queryMessage.Pack()
	if err != nil {
		return nil, err
	}
	httpRequest, err := http.NewRequestWithContext(requestContext, "POST", dohUpstream.url, bytes.NewReader(wireBytes))
	if err != nil {
		return nil, err
	}
	httpRequest.Header.Set("Content-Type", "application/dns-message")
	httpRequest.Header.Set("Accept", "application/dns-message")

	httpResponse, err := dohUpstream.client.Do(httpRequest)
	if err != nil {
		return nil, err
	}
	defer httpResponse.Body.Close()
	if httpResponse.StatusCode != http.StatusOK {
		return nil, io.ErrUnexpectedEOF
	}
	responseBody, err := io.ReadAll(io.LimitReader(httpResponse.Body, 1<<16))
	if err != nil {
		return nil, err
	}
	decodedResponse := new(dns.Msg)
	if err := decodedResponse.Unpack(responseBody); err != nil {
		return nil, err
	}
	return decodedResponse, nil
}
