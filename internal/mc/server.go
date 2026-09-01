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
	// Vanilla appearance
	MOTD            string
	VersionName     string
	VersionProtocol int
	MaxPlayers      int
	OnlinePlayers   int
	Sample          []map[string]string
	Favicon         string
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	log.Printf("dnsmc server listening on %s (suffix=%q)", s.Addr, s.Suffix)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				log.Printf("accept error: %v", err)
				continue
			}
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// 1. Handshake
	pid, payload, err := ReadFrame(conn)
	if err != nil {
		return
	}
	if pid != 0x00 {
		return
	}
	hs, err := ParseHandshake(payload)
	if err != nil {
		return
	}
	if hs.NextState != 1 {
		return
	}

	// 2. Status Request
	pid, payload, err = ReadFrame(conn)
	if err != nil {
		return
	}
	if pid != 0x00 {
		// allow ping without status request? require status
		return
	}
	_ = payload

	// 3. Decode DNS query from serverAddress
	bare := dnscodec.StripSuffix(hs.ServerAddress, s.Suffix)
	query, err := dnscodec.DecodeQuery(bare, "")
	if err != nil {
		// Distinguish vanilla ping vs malformed DNS query:
		// If serverAddress ends with suffix, it was intended as DNS query -> FORMERR
		// Otherwise it's a real Minecraft client -> vanilla MOTD.
		hasSuffix := s.Suffix != "" && dnscodec.StripSuffix(hs.ServerAddress, s.Suffix) != hs.ServerAddress
		if hasSuffix {
			log.Printf("decode failed for DNS query %q: %v", hs.ServerAddress, err)
			q := dnscodec.BuildErrorResponse(nil, 1) // FORMERR
			b64, _ := dnscodec.EncodeResponse(q)
			rawJSON := dnscodec.BuildStatusJSON(b64)
			_, _ = conn.Write(EncodeStatusResponseJSON(rawJSON))
			s.handlePing(conn)
			return
		}
		log.Printf("vanilla ping from %s (serverAddress=%q)", conn.RemoteAddr(), hs.ServerAddress)
		vanillaJSON := dnscodec.BuildVanillaStatusJSON(
			s.MOTD, s.VersionName, s.VersionProtocol,
			s.MaxPlayers, s.OnlinePlayers, s.Sample, s.Favicon,
		)
		_, _ = conn.Write(EncodeStatusResponseJSON(vanillaJSON))
		s.handlePing(conn)
		return
	}

	// 4. Resolve
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	resp, err := s.Resolver.Resolve(ctx, query)
	if err != nil {
		resp = dnscodec.BuildErrorResponse(query, 2) // SERVFAIL
	}
	b64, err := dnscodec.EncodeResponse(resp)
	if err != nil {
		b64, _ = dnscodec.EncodeResponse(dnscodec.BuildErrorResponse(query, 2))
	}
	rawJSON := dnscodec.BuildStatusJSON(b64)

	// Validate JSON
	var js json.RawMessage
	if json.Unmarshal(rawJSON, &js) != nil {
		log.Printf("invalid json generated")
		return
	}

	if _, err := conn.Write(EncodeStatusResponseJSON(rawJSON)); err != nil {
		return
	}

	// 5. Optional Ping/Pong
	s.handlePing(conn)
}

func (s *Server) handlePing(conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	pid, payload, err := ReadFrame(conn)
	if err != nil {
		return
	}
	if pid == 0x01 {
		ts, err := DecodePing(payload)
		if err != nil {
			return
		}
		_, _ = conn.Write(EncodePong(ts))
	}
}
