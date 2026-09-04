package upstream

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
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
	if err := validateResponse(decodedResponse, queryMessage); err != nil {
		return nil, err
	}
	return decodedResponse, nil
}

var errResponseMismatch = errors.New("doh: response does not match request")

// validateResponse checks that a decoded DNS response corresponds to the query
// that produced it (message ID and question section). The dns.Client code paths
// enforce this; DoH must too, otherwise a misbehaving/malicious upstream could
// answer a different question.
func validateResponse(decodedResponse, queryMessage *dns.Msg) error {
	if decodedResponse.Id != queryMessage.Id {
		return errResponseMismatch
	}
	if len(decodedResponse.Question) != 1 || len(queryMessage.Question) != 1 {
		return errResponseMismatch
	}
	responseQuestion := decodedResponse.Question[0]
	queryQuestion := queryMessage.Question[0]
	if !strings.EqualFold(dns.Fqdn(responseQuestion.Name), dns.Fqdn(queryQuestion.Name)) {
		return errResponseMismatch
	}
	if responseQuestion.Qtype != queryQuestion.Qtype || responseQuestion.Qclass != queryQuestion.Qclass {
		return errResponseMismatch
	}
	return nil
}
