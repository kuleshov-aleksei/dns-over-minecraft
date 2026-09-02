package dnscodec

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

var (
	base32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)
	base64Encoding = base64.StdEncoding
)

// EncodeQuery packs dns.Msg to wire and encodes as base32 for serverAddress.
func EncodeQuery(queryMessage *dns.Msg) (string, error) {
	wireBytes, err := queryMessage.Pack()
	if err != nil {
		return "", err
	}
	encodedQuery := base32Encoding.EncodeToString(wireBytes)
	return strings.ToLower(encodedQuery), nil
}

// DecodeQuery decodes serverAddress (with suffix already stripped) to dns.Msg.
// Handles dotted chunking (e.g. "abcd.efgh.mc" where bare was split into labels <=63).
func DecodeQuery(encodedQuery string, suffix string) (*dns.Msg, error) {
	if suffix != "" {
		if strings.HasSuffix(strings.ToLower(encodedQuery), strings.ToLower(suffix)) {
			encodedQuery = encodedQuery[:len(encodedQuery)-len(suffix)]
			encodedQuery = strings.TrimSuffix(encodedQuery, ".")
		}
	}
	// Remove label dots inserted for >63 char enc (hosts/DNS label limit)
	encodedQuery = strings.ReplaceAll(encodedQuery, ".", "")
	encodedQuery = strings.ToUpper(encodedQuery)
	wireBytes, err := base32Encoding.DecodeString(encodedQuery)
	if err != nil {
		return nil, fmt.Errorf("base32 decode: %w (input %q len %d, want base32(packed dns.Msg))", err, encodedQuery, len(encodedQuery))
	}
	if len(wireBytes) < 12 {
		return nil, fmt.Errorf("wire too short %d bytes (want >=12 header): dns: overflow unpacking uint16", len(wireBytes))
	}
	decodedMessage := new(dns.Msg)
	if err := decodedMessage.Unpack(wireBytes); err != nil {
		return nil, fmt.Errorf("%w (wire %d bytes, hex %x)", err, len(wireBytes), wireBytes)
	}
	return decodedMessage, nil
}

// StripSuffix removes suffix and trailing dot, returns bare encoded string (may contain dots for chunked).
func StripSuffix(serverAddress, suffix string) string {
	if suffix == "" {
		return serverAddress
	}
	lowerSuffix := strings.ToLower(suffix)
	lowerServerAddress := strings.ToLower(serverAddress)
	if strings.HasSuffix(lowerServerAddress, lowerSuffix) {
		trimmedAddress := serverAddress[:len(serverAddress)-len(suffix)]
		trimmedAddress = strings.TrimSuffix(trimmedAddress, ".")
		return trimmedAddress
	}
	return serverAddress
}

// EncodeResponse encodes dns.Msg wire to base64 for JSON description.
func EncodeResponse(responseMessage *dns.Msg) (string, error) {
	wireBytes, err := responseMessage.Pack()
	if err != nil {
		return "", err
	}
	return base64Encoding.EncodeToString(wireBytes), nil
}

// DecodeResponse decodes base64 string from description to dns.Msg.
func DecodeResponse(encodedResponse string) (*dns.Msg, error) {
	encodedResponse = strings.TrimSpace(encodedResponse)
	if encodedResponse == "" {
		return nil, errors.New("empty response")
	}
	wireBytes, err := base64Encoding.DecodeString(encodedResponse)
	if err != nil {
		return nil, err
	}
	decodedMessage := new(dns.Msg)
	if err := decodedMessage.Unpack(wireBytes); err != nil {
		return nil, err
	}
	return decodedMessage, nil
}

// BuildStatusJSON builds the MC status JSON with base64 response in description.
func BuildStatusJSON(base64Response string) []byte {
	statusJSON := `{"version":{"name":"dnsmc","protocol":765},"players":{"max":0,"online":0,"sample":[]},"description":{"text":"` + base64Response + `"}}`
	return []byte(statusJSON)
}

// BuildVanillaStatusJSON builds a vanilla-friendly status response for real MC clients.
func BuildVanillaStatusJSON(motd, versionName string, protocol, maxPlayers, onlinePlayers int, sample []map[string]string, favicon string) []byte {
	type sampleEntry struct {
		Name string `json:"name"`
		ID   string `json:"id"`
	}
	type status struct {
		Version struct {
			Name     string `json:"name"`
			Protocol int    `json:"protocol"`
		} `json:"version"`
		Players struct {
			Max    int           `json:"max"`
			Online int           `json:"online"`
			Sample []sampleEntry `json:"sample"`
		} `json:"players"`
		Description struct {
			Text string `json:"text"`
		} `json:"description"`
		Favicon string `json:"favicon,omitempty"`
	}
	var statusResponse status
	statusResponse.Version.Name = versionName
	statusResponse.Version.Protocol = protocol
	statusResponse.Players.Max = maxPlayers
	statusResponse.Players.Online = onlinePlayers
	for _, sampleEntryMap := range sample {
		statusResponse.Players.Sample = append(statusResponse.Players.Sample, sampleEntry{Name: sampleEntryMap["name"], ID: sampleEntryMap["id"]})
	}
	if statusResponse.Players.Sample == nil {
		statusResponse.Players.Sample = []sampleEntry{}
	}
	statusResponse.Description.Text = motd
	statusResponse.Favicon = favicon
	jsonBytes, _ := json.Marshal(statusResponse)
	return jsonBytes
}

// BuildErrorResponse builds a DNS error response (FORMERR etc).
func BuildErrorResponse(queryMessage *dns.Msg, responseCode int) *dns.Msg {
	errorResponse := new(dns.Msg)
	if queryMessage != nil {
		errorResponse.SetReply(queryMessage)
	}
	errorResponse.Rcode = responseCode
	return errorResponse
}
