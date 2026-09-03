package client

import (
	"context"
	"log"
	"sync"

	"github.com/miekg/dns"
)

// ListenAndServe runs a local DNS resolver (UDP + TCP) on listenAddress,
// forwarding every query through the Minecraft protocol to the configured
// dnsmc servers, with client-side caching in front.
func (clientInstance *Client) ListenAndServe(requestContext context.Context, listenAddress string) error {
	serveMux := dns.NewServeMux()
	serveMux.HandleFunc(".", clientInstance.handleDNS)

	serverList := make([]*dns.Server, 0, 2)
	errorChannel := make(chan error, 2)
	var waitGroup sync.WaitGroup

	for _, network := range []string{"udp", "tcp"} {
		serverInstance := &dns.Server{Addr: listenAddress, Net: network, Handler: serveMux}
		serverList = append(serverList, serverInstance)
		waitGroup.Add(1)
		go func(serverInstance *dns.Server) {
			defer waitGroup.Done()
			if err := serverInstance.ListenAndServe(); err != nil {
				errorChannel <- err
			}
		}(serverInstance)
	}

	log.Printf("dnsmc client listening on %s (udp/tcp, upstreams=%v suffix=%q)", listenAddress, clientInstance.servers, clientInstance.suffix)

	var firstError error
	select {
	case <-requestContext.Done():
	case serverError := <-errorChannel:
		firstError = serverError
	}

	for _, serverInstance := range serverList {
		_ = serverInstance.Shutdown()
	}
	waitGroup.Wait()
	return firstError
}

func (clientInstance *Client) handleDNS(responseWriter dns.ResponseWriter, queryMessage *dns.Msg) {
	queryMessage.RecursionDesired = true
	responseMessage, _ := clientInstance.Resolve(context.Background(), queryMessage)
	responseMessage.Id = queryMessage.Id
	responseMessage.Question = queryMessage.Question
	if writeErr := responseWriter.WriteMsg(responseMessage); writeErr != nil {
		log.Printf("client: write response: %v", writeErr)
	}
}