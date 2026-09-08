package client

import (
	"github.com/dns-over-minecraft/dns-over-minecraft/internal/vpndns"
	"github.com/miekg/dns"
)

// queryVpn tries each VPN DNS server in order over plain DNS (UDP, retrying
// truncated responses over TCP), returning the first successful answer.
func (clientInstance *Client) queryVpn(servers []vpndns.Server, queryMessage *dns.Msg) (*dns.Msg, error) {
	var lastError error
	for _, server := range servers {
		udpClient := &dns.Client{Timeout: vpnTimeout}
		responseMessage, _, err := udpClient.Exchange(queryMessage, server.Addr)
		if err == nil && responseMessage != nil {
			if responseMessage.Truncated {
				tcpClient := &dns.Client{Net: "tcp", Timeout: vpnTimeout}
				if tcpResponse, _, tcpErr := tcpClient.Exchange(queryMessage, server.Addr); tcpErr == nil {
					responseMessage = tcpResponse
				}
			}
			return responseMessage, nil
		}
		lastError = err
	}
	return nil, lastError
}
