package mc

import (
	crand "crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/dns-over-minecraft/dns-over-minecraft/internal/dnscodec"
	"github.com/miekg/dns"
)

const (
	maxSingleServerAddress = 255
	maxFragmentPieces      = 16
	fragmentMaxLabelLength = 60
)

func Query(serverAddress string, suffix string, passphrase string, queryMessage *dns.Msg) (*dns.Msg, error) {
	encodedQuery, err := dnscodec.EncodeQuery(queryMessage)
	if err != nil {
		return nil, err
	}
	authPrefix := authPrefixFor(passphrase)
	fullServerAddress := withSuffix(authPrefix+encodedQuery, suffix)
	if len(fullServerAddress) <= maxSingleServerAddress {
		statusResponse, err := exchange(serverAddress, fullServerAddress, 25565, queryMessage)
		if err != nil {
			return nil, err
		}
		return decodeStatusResponse(statusResponse, queryMessage)
	}
	return queryFragmented(serverAddress, suffix, passphrase, encodedQuery, queryMessage)
}

// authPrefixFor returns the "p.<passphrase>." server-address prefix the server's
// ACL requires, or the empty string when no passphrase is configured.
func authPrefixFor(passphrase string) string {
	if passphrase == "" {
		return ""
	}
	return passphraseMarker + passphrase + "."
}

func queryFragmented(serverAddress string, suffix string, passphrase string, encodedQuery string, queryMessage *dns.Msg) (*dns.Msg, error) {
	nonceBytes := make([]byte, 2)
	if _, err := crand.Read(nonceBytes); err != nil {
		return nil, err
	}
	nonce := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(nonceBytes))

	suffixWithDot := ""
	if suffix != "" {
		suffixWithDot = "." + strings.TrimPrefix(suffix, ".")
	}
	authPrefix := authPrefixFor(passphrase)
	// Budget the fragment address to stay within maxSingleServerAddress,
	// accounting for "p.<passphrase>.", "n.<nonce>." and the dots inserted by
	// label chunking.
	budget := maxSingleServerAddress - len(authPrefix) - len("n."+nonce+".") - len(suffixWithDot)
	maxPieceLength := budget * fragmentMaxLabelLength / (fragmentMaxLabelLength + 1)
	if maxPieceLength < 40 {
		maxPieceLength = 40
	}

	pieces := splitEncodedPieces(encodedQuery, maxPieceLength)
	if len(pieces) > maxFragmentPieces {
		return nil, fmt.Errorf("encoded query too large (%d fragments needed, max %d)", len(pieces), maxFragmentPieces)
	}

	var finalResponse *dns.Msg
	for index, piece := range pieces {
		fragmentAddress := authPrefix + "n." + nonce + "." + chunkLabels(piece, fragmentMaxLabelLength) + suffixWithDot
		serverPort := (index+1)<<8 | len(pieces)
		statusResponse, err := exchange(serverAddress, fragmentAddress, serverPort, queryMessage)
		if err != nil {
			return nil, err
		}
		if index == len(pieces)-1 {
			finalResponse, err = decodeStatusResponse(statusResponse, queryMessage)
			if err != nil {
				return nil, err
			}
		}
	}
	if finalResponse == nil {
		return nil, errors.New("no final fragment response")
	}
	return finalResponse, nil
}

func splitEncodedPieces(encodedQuery string, maxLength int) []string {
	var pieces []string
	for len(encodedQuery) > maxLength {
		pieces = append(pieces, encodedQuery[:maxLength])
		encodedQuery = encodedQuery[maxLength:]
	}
	if len(encodedQuery) > 0 {
		pieces = append(pieces, encodedQuery)
	}
	return pieces
}

func chunkLabels(text string, maxLabel int) string {
	if len(text) <= maxLabel {
		return text
	}
	var parts []string
	for len(text) > maxLabel {
		parts = append(parts, text[:maxLabel])
		text = text[maxLabel:]
	}
	if len(text) > 0 {
		parts = append(parts, text)
	}
	return strings.Join(parts, ".")
}

func withSuffix(encodedQuery, suffix string) string {
	if suffix == "" {
		return encodedQuery
	}
	if strings.HasPrefix(suffix, ".") {
		return encodedQuery + suffix
	}
	return encodedQuery + "." + suffix
}

// exchange performs a single Minecraft handshake + status request and returns
// the parsed status response.
func exchange(serverAddress string, address string, serverPort int, queryMessage *dns.Msg) (StatusResponse, error) {
	connection, err := net.DialTimeout("tcp", serverAddress, 3*time.Second)
	if err != nil {
		return StatusResponse{}, err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))

	handshake := Handshake{
		ProtocolVersion: 765,
		ServerAddress:   address,
		ServerPort:      uint16(serverPort),
		NextState:       1,
	}
	if _, err := connection.Write(EncodeHandshake(handshake)); err != nil {
		return StatusResponse{}, err
	}
	if _, err := connection.Write(EncodeStatusRequest()); err != nil {
		return StatusResponse{}, err
	}

	packetID, payload, err := ReadFrame(connection)
	if err != nil {
		return StatusResponse{}, err
	}
	if packetID != 0x00 {
		return StatusResponse{}, fmt.Errorf("unexpected packet id %d", packetID)
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
		return StatusResponse{}, fmt.Errorf("unmarshal status: %w body=%s", err, string(jsonBytes))
	}
	if statusResponse.Description.Text == "" {
		return StatusResponse{}, fmt.Errorf("empty description in response")
	}

	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = connection.Write(EncodePing(time.Now().UnixMilli()))

	return statusResponse, nil
}

func decodeStatusResponse(statusResponse StatusResponse, queryMessage *dns.Msg) (*dns.Msg, error) {
	responseMessage, err := dnscodec.DecodeResponse(statusResponse.Favicon)
	if err != nil {
		return nil, fmt.Errorf("decode dns response: %w", err)
	}
	responseMessage.Id = queryMessage.Id
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
func (byteReaderInstance *byteReader) Len() int {
	return len(byteReaderInstance.data) - byteReaderInstance.position
}
