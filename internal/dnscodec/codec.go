package dnscodec

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"github.com/miekg/dns"
)

var (
	b32 = base32.StdEncoding.WithPadding(base32.NoPadding)
	b64 = base64.StdEncoding
)

// EncodeQuery packs dns.Msg to wire and encodes as base32 for serverAddress.
func EncodeQuery(msg *dns.Msg) (string, error) {
	wire, err := msg.Pack()
	if err != nil {
		return "", err
	}
	enc := b32.EncodeToString(wire)
	return strings.ToLower(enc), nil
}

// DecodeQuery decodes serverAddress (with suffix already stripped) to dns.Msg.
func DecodeQuery(enc string, suffix string) (*dns.Msg, error) {
	// suffix handling is done by caller; here just decode
	if suffix != "" {
		if strings.HasSuffix(strings.ToLower(enc), strings.ToLower(suffix)) {
			enc = enc[:len(enc)-len(suffix)]
			// strip trailing dot
			enc = strings.TrimSuffix(enc, ".")
		} else {
			// if suffix required but missing, still try decode bare
		}
	}
	enc = strings.ToUpper(enc)
	// base32 requires upper
	wire, err := b32.DecodeString(enc)
	if err != nil {
		return nil, err
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(wire); err != nil {
		return nil, err
	}
	return msg, nil
}

// StripSuffix removes suffix and trailing dot, returns bare encoded string.
func StripSuffix(serverAddress, suffix string) string {
	if suffix == "" {
		return serverAddress
	}
	suffix = strings.ToLower(suffix)
	lower := strings.ToLower(serverAddress)
	if strings.HasSuffix(lower, suffix) {
		trimmed := serverAddress[:len(serverAddress)-len(suffix)]
		trimmed = strings.TrimSuffix(trimmed, ".")
		return trimmed
	}
	return serverAddress
}

// EncodeResponse encodes dns.Msg wire to base64 for JSON description.
func EncodeResponse(msg *dns.Msg) (string, error) {
	wire, err := msg.Pack()
	if err != nil {
		return "", err
	}
	return b64.EncodeToString(wire), nil
}

// DecodeResponse decodes base64 string from description to dns.Msg.
func DecodeResponse(s string) (*dns.Msg, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty response")
	}
	wire, err := b64.DecodeString(s)
	if err != nil {
		return nil, err
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(wire); err != nil {
		return nil, err
	}
	return msg, nil
}

// BuildStatusJSON builds the MC status JSON with base64 response in description.
func BuildStatusJSON(b64Response string) []byte {
	// Escape JSON via simple template; b64 is safe (no quotes)
	// Use players.sample for no extra data
	j := `{"version":{"name":"dnsmc","protocol":765},"players":{"max":0,"online":0,"sample":[]},"description":{"text":"` + b64Response + `"}}`
	return []byte(j)
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
	var s status
	s.Version.Name = versionName
	s.Version.Protocol = protocol
	s.Players.Max = maxPlayers
	s.Players.Online = onlinePlayers
	for _, e := range sample {
		s.Players.Sample = append(s.Players.Sample, sampleEntry{Name: e["name"], ID: e["id"]})
	}
	if s.Players.Sample == nil {
		s.Players.Sample = []sampleEntry{}
	}
	s.Description.Text = motd
	s.Favicon = favicon
	b, _ := json.Marshal(s)
	return b
}

// BuildErrorResponse builds a DNS error response (FORMERR etc).
func BuildErrorResponse(query *dns.Msg, rcode int) *dns.Msg {
	resp := new(dns.Msg)
	if query != nil {
		resp.SetReply(query)
	}
	resp.Rcode = rcode
	return resp
}
