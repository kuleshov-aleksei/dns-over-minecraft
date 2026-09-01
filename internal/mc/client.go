package mc

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/dns-over-minecraft/dns-over-minecraft/internal/dnscodec"
	"github.com/miekg/dns"
)

func Query(addr, suffix string, q *dns.Msg) (*dns.Msg, error) {
	enc, err := dnscodec.EncodeQuery(q)
	if err != nil {
		return nil, err
	}
	serverAddress := enc
	if suffix != "" {
		serverAddress = enc + suffix
		// ensure suffix starts with dot
		if suffix[0] != '.' {
			serverAddress = enc + "." + suffix
		}
	}
	if len(serverAddress) > 255 {
		return nil, fmt.Errorf("encoded query too long (%d > 255), qname too large for vanilla", len(serverAddress))
	}

	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// handshake
	hs := Handshake{
		ProtocolVersion: 765,
		ServerAddress:   serverAddress,
		ServerPort:      25565,
		NextState:       1,
	}
	if _, err := conn.Write(EncodeHandshake(hs)); err != nil {
		return nil, err
	}
	if _, err := conn.Write(EncodeStatusRequest()); err != nil {
		return nil, err
	}

	// read status response
	pid, payload, err := ReadFrame(conn)
	if err != nil {
		return nil, err
	}
	if pid != 0x00 {
		return nil, fmt.Errorf("unexpected packet id %d", pid)
	}
	// payload is either len-prefixed json or raw json
	var jsonBytes []byte
	// try to handle both: if payload starts with '{', it's raw; else VarInt len + json
	if len(payload) > 0 && payload[0] == '{' {
		jsonBytes = payload
	} else {
		// read VarInt length
		r := newByteReader(payload)
		length, _, err := ReadVarInt(r)
		if err == nil {
			rest, _ := io.ReadAll(r)
			if len(rest) >= length {
				jsonBytes = rest[:length]
			} else {
				jsonBytes = rest
			}
		} else {
			jsonBytes = payload
		}
	}

	var sr StatusResponse
	if err := json.Unmarshal(jsonBytes, &sr); err != nil {
		return nil, fmt.Errorf("unmarshal status: %w body=%s", err, string(jsonBytes))
	}
	if sr.Description.Text == "" {
		return nil, fmt.Errorf("empty description in response")
	}
	resp, err := dnscodec.DecodeResponse(sr.Description.Text)
	if err != nil {
		return nil, fmt.Errorf("decode dns response: %w", err)
	}
	resp.Id = q.Id

	// ping/pong to cleanly close (optional)
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Write(EncodePing(time.Now().UnixMilli()))
	// ignore pong

	return resp, nil
}

// helper to implement io.Reader for VarInt
type byteReader struct {
	data []byte
	pos  int
}

func newByteReader(b []byte) *byteReader { return &byteReader{data: b} }
func (b *byteReader) Read(p []byte) (int, error) {
	if b.pos >= len(b.data) {
		return 0, io.EOF
	}
	n := copy(p, b.data[b.pos:])
	b.pos += n
	return n, nil
}
func (b *byteReader) Len() int { return len(b.data) - b.pos }
