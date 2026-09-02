package mc

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"time"

	"github.com/dns-over-minecraft/dns-over-minecraft/internal/dnscodec"
	"github.com/dns-over-minecraft/dns-over-minecraft/internal/resolver"
)

type Server struct {
	Addr     string
	Suffix   string
	Resolver *resolver.Resolver
	MOTD            string
	VersionName     string
	VersionProtocol int
	MaxPlayers      int
	OnlinePlayers   int
	Sample          []map[string]string
	Favicon         string
}

func (serverInstance *Server) ListenAndServe(requestContext context.Context) error {
	listener, err := net.Listen("tcp", serverInstance.Addr)
	if err != nil {
		return err
	}
	defer listener.Close()
	log.Printf("dnsmc server listening on %s (suffix=%q)", serverInstance.Addr, serverInstance.Suffix)

	go func() {
		<-requestContext.Done()
		listener.Close()
	}()

	for {
		connection, err := listener.Accept()
		if err != nil {
			select {
			case <-requestContext.Done():
				return nil
			default:
				log.Printf("accept error: %v", err)
				continue
			}
		}
		go serverInstance.handleConn(connection)
	}
}

func (serverInstance *Server) handleConn(connection net.Conn) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))

	packetID, payload, err := ReadFrame(connection)
	if err != nil {
		return
	}
	if packetID != 0x00 {
		return
	}
	handshake, err := ParseHandshake(payload)
	if err != nil {
		return
	}
	if handshake.NextState != 1 {
		return
	}

	packetID, payload, err = ReadFrame(connection)
	if err != nil {
		return
	}
	if packetID != 0x00 {
		return
	}
	_ = payload

	bareAddress := dnscodec.StripSuffix(handshake.ServerAddress, serverInstance.Suffix)
	queryMessage, err := dnscodec.DecodeQuery(bareAddress, "")
	if err != nil {
		hasSuffix := serverInstance.Suffix != "" && dnscodec.StripSuffix(handshake.ServerAddress, serverInstance.Suffix) != handshake.ServerAddress
		if hasSuffix {
			bareLength := len(dnscodec.StripSuffix(handshake.ServerAddress, serverInstance.Suffix))
			log.Printf("decode failed for DNS query %q (bare %d chars): %v -- hint: generate with 'dnsmc encode <name> [type]' (want base32(packed dns.Msg)+suffix)", handshake.ServerAddress, bareLength, err)
			errorResponse := dnscodec.BuildErrorResponse(nil, 1)
			base64Response, _ := dnscodec.EncodeResponse(errorResponse)
			rawJSON := dnscodec.BuildStatusJSON(base64Response)
			_, _ = connection.Write(EncodeStatusResponseJSON(rawJSON))
			serverInstance.handlePing(connection)
			return
		}
		log.Printf("vanilla ping from %s (serverAddress=%q)", connection.RemoteAddr(), handshake.ServerAddress)
		vanillaJSON := dnscodec.BuildVanillaStatusJSON(
			serverInstance.MOTD, serverInstance.VersionName, serverInstance.VersionProtocol,
			serverInstance.MaxPlayers, serverInstance.OnlinePlayers, serverInstance.Sample, serverInstance.Favicon,
		)
		_, _ = connection.Write(EncodeStatusResponseJSON(vanillaJSON))
		serverInstance.handlePing(connection)
		return
	}

	timeoutContext, cancelFunc := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancelFunc()
	responseMessage, err := serverInstance.Resolver.Resolve(timeoutContext, queryMessage)
	if err != nil {
		responseMessage = dnscodec.BuildErrorResponse(queryMessage, 2)
	}
	base64Response, err := dnscodec.EncodeResponse(responseMessage)
	if err != nil {
		base64Response, _ = dnscodec.EncodeResponse(dnscodec.BuildErrorResponse(queryMessage, 2))
	}
	rawJSON := dnscodec.BuildStatusJSON(base64Response)

	var jsonRawMessage json.RawMessage
	if json.Unmarshal(rawJSON, &jsonRawMessage) != nil {
		log.Printf("invalid json generated")
		return
	}

	if _, err := connection.Write(EncodeStatusResponseJSON(rawJSON)); err != nil {
		return
	}

	serverInstance.handlePing(connection)
}

func (serverInstance *Server) handlePing(connection net.Conn) {
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	packetID, payload, err := ReadFrame(connection)
	if err != nil {
		return
	}
	if packetID == 0x01 {
		timestamp, err := DecodePing(payload)
		if err != nil {
			return
		}
		_, _ = connection.Write(EncodePong(timestamp))
	}
}
