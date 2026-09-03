package dnscodec

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
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

const (
	// magicMinimal (v1) carries no EDNS; magicEdns (v2) adds a 1-byte EDNS
	// buffer size field right after the magic so the server can size upstream
	// requests. Only the buffer size is propagated; DNSSEC (DO/CD) is not.
	magicMinimal byte = 0xFF
	magicEdns    byte = 0xFE
	tldRaw       byte = 0x00
	// 1..99 allocated, 100..254 reserved, 255 == magic
	tldReservedStart byte = 100
)

// 99 TLDs -> codes 1..99
var tldList = []string{
	"com", "net", "org", "info", "biz", "edu", "gov", "mil", "int", "arpa",
	"coop", "museum", "aero", "jobs", "cat", "travel", "asia", "tel", "mobi", "name",
	"pro", "post", "xxx", "xyz", "top", "shop", "online", "store", "site", "vip",
	"sbs", "app", "click", "bond", "lol", "live", "icu", "cfd", "club", "space",
	"dev", "cyou", "fun", "tech", "cloud", "life", "today", "world", "buzz", "blog",
	"digital", "work", "link", "website", "one", "art", "autos", "lat", "help", "skin",
	"studio", "group", "bet", "rest", "win", "ink", "garden", "wiki", "beer", "homes",
	"agency", "pics", "ltd", "makeup", "email", "run", "xin", "cam", "solutions", "fyi",
	"tokyo", "media", "services", "beauty", "company",
	"news", "boats", "fit", "network", "qpon", "bid", "best", "zone", "casa", "quest",
	"academy", "love", "international", "microsoft",
}

var (
	tldToCode map[string]byte
	codeToTLD map[byte]string
)

func init() {
	tldToCode = make(map[string]byte, len(tldList))
	codeToTLD = make(map[byte]string, len(tldList))
	for index, tldEntry := range tldList {
		code := byte(index + 1)
		tldToCode[tldEntry] = code
		codeToTLD[code] = tldEntry
	}
}

// EncodeQuery packs dns.Msg question into minimal wire and encodes as base32 for serverAddress.
// Format: MAGIC(0xFF) || TLD_CODE(1) || VARINT(QTYPE) || NAME_PART(wire labels 0-terminated)
// TLD_CODE==0 means NAME_PART is full QNAME wire; else NAME_PART is prefix without last label.
func EncodeQuery(queryMessage *dns.Msg) (string, error) {
	if len(queryMessage.Question) == 0 {
		return "", errors.New("no question")
	}
	question := queryMessage.Question[0]
	if question.Qclass != dns.ClassINET {
		return "", fmt.Errorf("unsupported qclass %d (only IN)", question.Qclass)
	}
	domainName := strings.ToLower(strings.TrimSuffix(question.Name, "."))
	if domainName == "" {
		return "", errors.New("empty qname")
	}
	labels := strings.Split(domainName, ".")
	if len(labels) == 0 {
		return "", errors.New("empty labels")
	}
	for _, labelEntry := range labels {
		if len(labelEntry) == 0 || len(labelEntry) > 63 {
			return "", fmt.Errorf("invalid label %q", labelEntry)
		}
	}
	lastLabel := labels[len(labels)-1]
	code, exists := tldToCode[lastLabel]
	var namePart []byte
	if exists {
		prefixLabels := labels[:len(labels)-1]
		namePart = packLabels(prefixLabels)
	} else {
		code = tldRaw
		namePart = packLabels(labels)
	}
	var buffer bytes.Buffer
	if optRecord := queryMessage.IsEdns0(); optRecord != nil {
		buffer.WriteByte(magicEdns)
		buffer.WriteByte(encodeEdnsSize(optRecord))
	} else {
		buffer.WriteByte(magicMinimal)
	}
	buffer.WriteByte(code)
	var varintBuffer [binary.MaxVarintLen64]byte
	varintLength := binary.PutUvarint(varintBuffer[:], uint64(question.Qtype))
	buffer.Write(varintBuffer[:varintLength])
	buffer.Write(namePart)
	encodedQuery := base32Encoding.EncodeToString(buffer.Bytes())
	return strings.ToLower(encodedQuery), nil
}

// encodeEdnsSize maps a client's advertised EDNS UDP buffer size to a single
// byte (size/256, so 512->2, 4096->16). Sub-256 precision is lost but a
// conservative (smaller) size is always safe.
func encodeEdnsSize(optRecord *dns.OPT) byte {
	size := optRecord.UDPSize()
	if size < 512 {
		size = 512
	}
	if size > 65535 {
		size = 65535
	}
	return byte(size / 256)
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
	encodedQuery = strings.ReplaceAll(encodedQuery, ".", "")
	encodedQuery = strings.ToUpper(encodedQuery)
	wireBytes, err := base32Encoding.DecodeString(encodedQuery)
	if err != nil {
		return nil, fmt.Errorf("base32 decode: %w (input %q len %d)", err, encodedQuery, len(encodedQuery))
	}
	if len(wireBytes) == 0 {
		return nil, errors.New("empty wire")
	}
	var code byte
	var ednsSize uint16
	var payloadStart int
	switch wireBytes[0] {
	case magicMinimal:
		if len(wireBytes) < 3 {
			return nil, fmt.Errorf("wire too short %d (want >=3 minimal)", len(wireBytes))
		}
		code = wireBytes[1]
		payloadStart = 2
	case magicEdns:
		if len(wireBytes) < 4 {
			return nil, fmt.Errorf("wire too short %d (want >=4 edns format)", len(wireBytes))
		}
		ednsSize = uint16(wireBytes[1]) * 256
		code = wireBytes[2]
		payloadStart = 3
	default:
		return nil, fmt.Errorf("invalid magic 0x%02x (want 0x%02x minimal or 0x%02x edns format)", wireBytes[0], magicMinimal, magicEdns)
	}
	if code >= tldReservedStart && code <= 254 {
		return nil, fmt.Errorf("reserved TLD code %d (100-254)", code)
	}
	reader := bytes.NewReader(wireBytes[payloadStart:])
	qtypeValue, err := binary.ReadUvarint(reader)
	if err != nil {
		return nil, fmt.Errorf("read qtype varint: %w", err)
	}
	if qtypeValue > 65535 {
		return nil, fmt.Errorf("qtype out of range %d", qtypeValue)
	}
	remainingLength := reader.Len()
	namePart := make([]byte, remainingLength)
	if _, err := reader.Read(namePart); err != nil {
		return nil, fmt.Errorf("read name part: %w", err)
	}
	if len(namePart) == 0 || namePart[len(namePart)-1] != 0 {
		return nil, fmt.Errorf("name part not 0-terminated (hex %x)", namePart)
	}
	var domainName string
	if code == tldRaw {
		unpackedDomain, err := unpackLabels(namePart)
		if err != nil {
			return nil, err
		}
		domainName = unpackedDomain
	} else {
		tldEntry, exists := codeToTLD[code]
		if !exists {
			return nil, fmt.Errorf("unknown TLD code %d", code)
		}
		prefixDomain := ""
		if len(namePart) > 1 {
			unpackedPrefix, err := unpackLabels(namePart)
			if err != nil {
				return nil, err
			}
			prefixDomain = unpackedPrefix
		} else if len(namePart) == 1 && namePart[0] == 0 {
			prefixDomain = ""
		} else {
			return nil, fmt.Errorf("invalid prefix name part hex %x", namePart)
		}
		if prefixDomain == "" {
			domainName = tldEntry
		} else {
			domainName = prefixDomain + "." + tldEntry
		}
	}
	decodedMessage := new(dns.Msg)
	decodedMessage.SetQuestion(dns.Fqdn(domainName), uint16(qtypeValue))
	decodedMessage.RecursionDesired = true
	decodedMessage.Id = 0
	if ednsSize > 0 {
		decodedMessage.SetEdns0(ednsSize, false)
	}
	return decodedMessage, nil
}

func packLabels(labels []string) []byte {
	if len(labels) == 0 {
		return []byte{0}
	}
	var buffer bytes.Buffer
	for _, labelEntry := range labels {
		buffer.WriteByte(byte(len(labelEntry)))
		buffer.WriteString(labelEntry)
	}
	buffer.WriteByte(0)
	return buffer.Bytes()
}

func unpackLabels(wire []byte) (string, error) {
	if len(wire) == 0 {
		return "", errors.New("empty label wire")
	}
	var labels []string
	position := 0
	for {
		if position >= len(wire) {
			return "", errors.New("truncated label wire")
		}
		labelLength := int(wire[position])
		position++
		if labelLength == 0 {
			break
		}
		if labelLength > 63 {
			return "", fmt.Errorf("label too long %d", labelLength)
		}
		if position+labelLength > len(wire) {
			return "", fmt.Errorf("label overflow %d at %d", labelLength, position)
		}
		labelEntry := string(wire[position : position+labelLength])
		labels = append(labels, labelEntry)
		position += labelLength
	}
	if position != len(wire) {
		return "", fmt.Errorf("trailing bytes after 0 terminator %d", len(wire)-position)
	}
	return strings.Join(labels, "."), nil
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

// StripOPT removes the EDNS OPT pseudo-record from a message's extra section.
// RFC 6891: a server MUST NOT include an OPT RR in a response unless the
// request carried one, so responses to plain queries have it removed.
func StripOPT(responseMessage *dns.Msg) {
	if responseMessage == nil {
		return
	}
	filteredExtra := make([]dns.RR, 0, len(responseMessage.Extra))
	for _, resourceRecord := range responseMessage.Extra {
		if _, isOptRecord := resourceRecord.(*dns.OPT); isOptRecord {
			continue
		}
		filteredExtra = append(filteredExtra, resourceRecord)
	}
	responseMessage.Extra = filteredExtra
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
