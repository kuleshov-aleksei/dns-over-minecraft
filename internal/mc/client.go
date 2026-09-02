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

func Query(serverAddress string, suffix string, queryMessage *dns.Msg) (*dns.Msg, error) {
	encodedQuery, err := dnscodec.EncodeQuery(queryMessage)
	if err != nil {
		return nil, err
	}
	fullServerAddress := encodedQuery
	if suffix != "" {
		fullServerAddress = encodedQuery + suffix
		if suffix[0] != '.' {
			fullServerAddress = encodedQuery + "." + suffix
		}
	}
	if len(fullServerAddress) > 255 {
		return nil, fmt.Errorf("encoded query too long (%d > 255), qname too large for vanilla", len(fullServerAddress))
	}

	connection, err := net.DialTimeout("tcp", serverAddress, 3*time.Second)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))

	handshake := Handshake{
		ProtocolVersion: 765,
		ServerAddress:   fullServerAddress,
		ServerPort:      25565,
		NextState:       1,
	}
	if _, err := connection.Write(EncodeHandshake(handshake)); err != nil {
		return nil, err
	}
	if _, err := connection.Write(EncodeStatusRequest()); err != nil {
		return nil, err
	}

	packetID, payload, err := ReadFrame(connection)
	if err != nil {
		return nil, err
	}
	if packetID != 0x00 {
		return nil, fmt.Errorf("unexpected packet id %d", packetID)
	}
	var jsonBytes []byte
	if len(payload) > 0 && payload[0] == '{' {
		jsonBytes = payload
	} else {
		byteReader := newByteReader(payload)
		length, _, err := ReadVarInt(byteReader)
		if err == nil {
			remainingBytes, _ := io.ReadAll(byteReader)
			if len(remainingBytes) >= length {
				jsonBytes = remainingBytes[:length]
			} else {
				jsonBytes = remainingBytes
			}
		} else {
			jsonBytes = payload
		}
	}

	var statusResponse StatusResponse
	if err := json.Unmarshal(jsonBytes, &statusResponse); err != nil {
		return nil, fmt.Errorf("unmarshal status: %w body=%s", err, string(jsonBytes))
	}
	if statusResponse.Description.Text == "" {
		return nil, fmt.Errorf("empty description in response")
	}
	responseMessage, err := dnscodec.DecodeResponse(statusResponse.Description.Text)
	if err != nil {
		return nil, fmt.Errorf("decode dns response: %w", err)
	}
	responseMessage.Id = queryMessage.Id

	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = connection.Write(EncodePing(time.Now().UnixMilli()))

	return responseMessage, nil
}

// helper to implement io.Reader for VarInt
type byteReader struct {
	data     []byte
	position int
}

func newByteReader(buffer []byte) *byteReader { return &byteReader{data: buffer} }
func (byteReaderInstance *byteReader) Read(destination []byte) (int, error) {
	if byteReaderInstance.position >= len(byteReaderInstance.data) {
		return 0, io.EOF
	}
	bytesCopied := copy(destination, byteReaderInstance.data[byteReaderInstance.position:])
	byteReaderInstance.position += bytesCopied
	return bytesCopied, nil
}
func (byteReaderInstance *byteReader) Len() int { return len(byteReaderInstance.data) - byteReaderInstance.position }
