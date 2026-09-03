package dnscodec

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

	// responseMagic leads every compact response payload so a decoder can
	// distinguish it from any other base64 blob (e.g. a real PNG icon) found
	// in the favicon field.
	responseMagic byte = 0xD1
	// FaviconDataURIPrefix wraps the payload in the status favicon field so
	// the response looks like a normal Minecraft server icon.
	FaviconDataURIPrefix = "data:image/png;base64,"

	// Name tokens for the compact response wire: "dropping the owner" the way
	// Cloudflare described in https://blog.cloudflare.com/dns-cache-memory-optimization-1111/.
	// Most records share the queried owner, so that name collapses to a single byte.
	nameTokenQname   byte = 0x00 // owner == question name
	nameTokenPrev    byte = 0x01 // owner == previous RR owner
	nameTokenTable   byte = 0x02 // followed by a uvarint index into the name table
	nameTokenLiteral byte = 0x03 // followed by wire labels, appended to the table
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

// EncodeResponse encodes a dns.Msg as a compact, owner-dropped payload and
// returns it base64-encoded for the status favicon field.
func EncodeResponse(responseMessage *dns.Msg) (string, error) {
	if responseMessage == nil {
		return "", errors.New("nil response message")
	}
	compactWire, err := packCompactResponse(responseMessage)
	if err != nil {
		return "", err
	}
	return base64Encoding.EncodeToString(compactWire), nil
}

// DecodeResponse decodes a base64 compact response payload (optionally wrapped
// in the favicon data-URI prefix) back into a dns.Msg.
func DecodeResponse(encodedResponse string) (*dns.Msg, error) {
	encodedResponse = strings.TrimSpace(encodedResponse)
	encodedResponse = strings.TrimPrefix(encodedResponse, FaviconDataURIPrefix)
	if encodedResponse == "" {
		return nil, errors.New("empty response")
	}
	payload, err := base64Encoding.DecodeString(encodedResponse)
	if err != nil {
		return nil, err
	}
	return unpackCompactResponse(payload)
}

// packCompactResponse serializes a message with the owner-dropped layout:
//
//	magic(0xD1) uvarint(rcode) flags uvarint(qd) uvarint(an) uvarint(ns) uvarint(ar)
//	per question: name-token uvarint(qtype) uvarint(qclass)
//	per RR:       name-token uvarint(type) uvarint(class) uvarint(ttl) uvarint(rdlen) rdata
//
// RDATA is copied verbatim from an uncompressed pack, so embedded names are
// fully expanded (no compression pointers dangling into a foreign message).
func packCompactResponse(responseMessage *dns.Msg) ([]byte, error) {
	qnameWire, err := packDomainNameWire(responseMessage.Question)
	if err != nil {
		return nil, err
	}
	nameTable := make([][]byte, 0, 8)
	if len(qnameWire) > 0 {
		nameTable = append(nameTable, qnameWire)
	}
	var previousOwnerWire []byte

	encodeName := func(buffer *bytes.Buffer, nameWire []byte) error {
		if len(qnameWire) > 0 && bytes.Equal(nameWire, qnameWire) {
			buffer.WriteByte(nameTokenQname)
			return nil
		}
		if len(previousOwnerWire) > 0 && bytes.Equal(nameWire, previousOwnerWire) {
			buffer.WriteByte(nameTokenPrev)
			return nil
		}
		for index, knownWire := range nameTable {
			if bytes.Equal(knownWire, nameWire) {
				buffer.WriteByte(nameTokenTable)
				writeUvarint(buffer, uint64(index))
				return nil
			}
		}
		buffer.WriteByte(nameTokenLiteral)
		buffer.Write(nameWire)
		nameTable = append(nameTable, nameWire)
		return nil
	}

	var buffer bytes.Buffer
	buffer.WriteByte(responseMagic)
	writeUvarint(&buffer, uint64(responseMessage.Rcode))
	buffer.WriteByte(packFlags(responseMessage))
	writeUvarint(&buffer, uint64(len(responseMessage.Question)))
	writeUvarint(&buffer, uint64(len(responseMessage.Answer)))
	writeUvarint(&buffer, uint64(len(responseMessage.Ns)))
	writeUvarint(&buffer, uint64(len(responseMessage.Extra)))

	for _, question := range responseMessage.Question {
		// The question name is the qname itself; emit it as a literal because
		// the decoder has nothing to reference it from yet.
		questionNameWire, err := packDomainName(question.Name)
		if err != nil {
			return nil, err
		}
		buffer.WriteByte(nameTokenLiteral)
		buffer.Write(questionNameWire)
		writeUvarint(&buffer, uint64(question.Qtype))
		writeUvarint(&buffer, uint64(question.Qclass))
	}

	rdataScratch := make([]byte, 256<<10)
	encodeSection := func(section []dns.RR) error {
		for _, resourceRecord := range section {
			header := resourceRecord.Header()
			ownerWire, err := packDomainName(header.Name)
			if err != nil {
				return err
			}
			if err := encodeName(&buffer, ownerWire); err != nil {
				return err
			}
			writeUvarint(&buffer, uint64(header.Rrtype))
			writeUvarint(&buffer, uint64(header.Class))
			writeUvarint(&buffer, uint64(header.Ttl))
			rdata, err := packRdata(resourceRecord, rdataScratch)
			if err != nil {
				return err
			}
			writeUvarint(&buffer, uint64(len(rdata)))
			buffer.Write(rdata)
			previousOwnerWire = ownerWire
		}
		return nil
	}
	for _, section := range [][]dns.RR{responseMessage.Answer, responseMessage.Ns, responseMessage.Extra} {
		if err := encodeSection(section); err != nil {
			return nil, err
		}
	}
	return buffer.Bytes(), nil
}

// unpackCompactResponse parses the compact layout and rebuilds a standard DNS
// wire message (fully expanded names) for dns.Msg.Unpack.
func unpackCompactResponse(payload []byte) (*dns.Msg, error) {
	reader := bytes.NewReader(payload)
	firstByte, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}
	if firstByte != responseMagic {
		return nil, fmt.Errorf("not a dnsmc response payload (bad magic 0x%02X)", firstByte)
	}
	rcodeValue, err := binary.ReadUvarint(reader)
	if err != nil {
		return nil, fmt.Errorf("read rcode: %w", err)
	}
	flagsByte, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("read flags: %w", err)
	}
	sectionCounts := make([]uint64, 4)
	for index := range sectionCounts {
		sectionCounts[index], err = binary.ReadUvarint(reader)
		if err != nil {
			return nil, fmt.Errorf("read section count %d: %w", index, err)
		}
	}

	var qnameWire []byte
	var previousOwnerWire []byte
	nameTable := make([][]byte, 0, 8)

	readName := func() ([]byte, error) {
		token, err := reader.ReadByte()
		if err != nil {
			return nil, err
		}
		switch token {
		case nameTokenQname:
			if len(qnameWire) == 0 {
				return nil, errors.New("qname token before any question")
			}
			return qnameWire, nil
		case nameTokenPrev:
			if len(previousOwnerWire) == 0 {
				return nil, errors.New("previous-owner token before any RR")
			}
			return previousOwnerWire, nil
		case nameTokenTable:
			index, err := binary.ReadUvarint(reader)
			if err != nil {
				return nil, err
			}
			if index >= uint64(len(nameTable)) {
				return nil, fmt.Errorf("name table index %d out of range", index)
			}
			return nameTable[index], nil
		case nameTokenLiteral:
			wire, err := readWireNameBytes(reader)
			if err != nil {
				return nil, err
			}
			nameTable = append(nameTable, wire)
			return wire, nil
		default:
			return nil, fmt.Errorf("unknown name token 0x%02X", token)
		}
	}

	var wireBuffer bytes.Buffer
	wireBuffer.Write([]byte{0x00, 0x00}) // message ID
	flagsWire := unpackFlags(flagsByte, rcodeValue)
	wireBuffer.Write([]byte{byte(flagsWire >> 8), byte(flagsWire & 0xFF)})
	for _, count := range sectionCounts {
		wireBuffer.Write([]byte{byte(count >> 8), byte(count & 0xFF)})
	}

	for index := uint64(0); index < sectionCounts[0]; index++ {
		nameWire, err := readName()
		if err != nil {
			return nil, fmt.Errorf("question %d name: %w", index, err)
		}
		if index == 0 {
			qnameWire = nameWire
		}
		qtype, err := binary.ReadUvarint(reader)
		if err != nil {
			return nil, err
		}
		qclass, err := binary.ReadUvarint(reader)
		if err != nil {
			return nil, err
		}
		wireBuffer.Write(nameWire)
		writeUint16(&wireBuffer, uint16(qtype))
		writeUint16(&wireBuffer, uint16(qclass))
	}

	readSection := func(count uint64) error {
		for index := uint64(0); index < count; index++ {
			ownerWire, err := readName()
			if err != nil {
				return fmt.Errorf("RR %d name: %w", index, err)
			}
			previousOwnerWire = ownerWire
			rrType, err := binary.ReadUvarint(reader)
			if err != nil {
				return err
			}
			class, err := binary.ReadUvarint(reader)
			if err != nil {
				return err
			}
			ttl, err := binary.ReadUvarint(reader)
			if err != nil {
				return err
			}
			rdLength, err := binary.ReadUvarint(reader)
			if err != nil {
				return err
			}
			if rdLength > uint64(reader.Len()) {
				return fmt.Errorf("rdlength %d exceeds remaining payload %d", rdLength, reader.Len())
			}
			rdata := make([]byte, rdLength)
			if _, err := io.ReadFull(reader, rdata); err != nil {
				return err
			}
			wireBuffer.Write(ownerWire)
			writeUint16(&wireBuffer, uint16(rrType))
			writeUint16(&wireBuffer, uint16(class))
			var ttlBytes [4]byte
			binary.BigEndian.PutUint32(ttlBytes[:], uint32(ttl))
			wireBuffer.Write(ttlBytes[:])
			writeUint16(&wireBuffer, uint16(rdLength))
			wireBuffer.Write(rdata)
		}
		return nil
	}
	for _, count := range sectionCounts[1:] {
		if err := readSection(count); err != nil {
			return nil, err
		}
	}

	decodedMessage := new(dns.Msg)
	if err := decodedMessage.Unpack(wireBuffer.Bytes()); err != nil {
		return nil, err
	}
	return decodedMessage, nil
}

// packDomainNameWire returns the uncompressed wire bytes of the first question
// name, or nil when the message carries no question (there is no qname to drop
// to then).
func packDomainNameWire(questions []dns.Question) ([]byte, error) {
	if len(questions) == 0 {
		return nil, nil
	}
	return packDomainName(questions[0].Name)
}

func packDomainName(name string) ([]byte, error) {
	scratch := make([]byte, 256)
	packedLength, err := dns.PackDomainName(name, scratch, 0, nil, false)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), scratch[:packedLength]...), nil
}

// packRdata extracts the RDATA bytes of a record with all embedded names fully
// expanded, so it can be copied verbatim into the compact payload.
func packRdata(resourceRecord dns.RR, scratch []byte) ([]byte, error) {
	packedEnd, err := dns.PackRR(resourceRecord, scratch, 0, nil, false)
	if err != nil {
		return nil, err
	}
	ownerLength, err := dns.PackDomainName(resourceRecord.Header().Name, scratch, 0, nil, false)
	if err != nil {
		return nil, err
	}
	return scratch[ownerLength+10 : packedEnd], nil
}

// readWireNameBytes reads a wire-format domain name (labels + terminator) and
// returns the raw bytes, terminator included.
func readWireNameBytes(reader *bytes.Reader) ([]byte, error) {
	var wire []byte
	for {
		labelLength, err := reader.ReadByte()
		if err != nil {
			return nil, err
		}
		wire = append(wire, labelLength)
		if labelLength == 0 {
			break
		}
		if labelLength > 63 {
			return nil, fmt.Errorf("label too long %d", labelLength)
		}
		if int(labelLength) > reader.Len() {
			return nil, fmt.Errorf("label length %d exceeds remaining payload %d", labelLength, reader.Len())
		}
		labelBytes := make([]byte, labelLength)
		if _, err := io.ReadFull(reader, labelBytes); err != nil {
			return nil, err
		}
		wire = append(wire, labelBytes...)
	}
	if len(wire) > 255 {
		return nil, fmt.Errorf("name too long %d", len(wire))
	}
	return wire, nil
}

func writeUvarint(buffer *bytes.Buffer, value uint64) {
	var varintBuffer [binary.MaxVarintLen64]byte
	length := binary.PutUvarint(varintBuffer[:], value)
	buffer.Write(varintBuffer[:length])
}

func writeUint16(buffer *bytes.Buffer, value uint16) {
	var uint16Bytes [2]byte
	binary.BigEndian.PutUint16(uint16Bytes[:], value)
	buffer.Write(uint16Bytes[:])
}

// packFlags packs message flags into a single byte (AA RA RD TC AD CD).
func packFlags(responseMessage *dns.Msg) byte {
	var flags byte
	if responseMessage.Authoritative {
		flags |= 1 << 0
	}
	if responseMessage.RecursionAvailable {
		flags |= 1 << 1
	}
	if responseMessage.RecursionDesired {
		flags |= 1 << 2
	}
	if responseMessage.Truncated {
		flags |= 1 << 3
	}
	if responseMessage.AuthenticatedData {
		flags |= 1 << 4
	}
	if responseMessage.CheckingDisabled {
		flags |= 1 << 5
	}
	return flags
}

// unpackFlags rebuilds the DNS wire-format header flags word (QR set) from the
// compact flags byte and rcode.
func unpackFlags(flagsByte byte, rcode uint64) uint16 {
	var flagsWire uint16 = 0x8000 // QR
	if flagsByte&(1<<0) != 0 {
		flagsWire |= 0x0400 // AA
	}
	if flagsByte&(1<<1) != 0 {
		flagsWire |= 0x0080 // RA
	}
	if flagsByte&(1<<2) != 0 {
		flagsWire |= 0x0100 // RD
	}
	if flagsByte&(1<<3) != 0 {
		flagsWire |= 0x0200 // TC
	}
	if flagsByte&(1<<4) != 0 {
		flagsWire |= 0x0020 // AD
	}
	if flagsByte&(1<<5) != 0 {
		flagsWire |= 0x0010 // CD
	}
	return flagsWire | uint16(rcode&0x0F)
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

// BuildStatusJSON builds the MC status JSON for a dnsmc response. The motd is
// presented as a normal server description while the compact response payload
// rides in the favicon field, so the status looks like a normal Minecraft
// server to packet analysis.
func BuildStatusJSON(motd string, payloadBase64 string) []byte {
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
		Favicon string `json:"favicon"`
	}
	var statusResponse status
	statusResponse.Version.Name = "dnsmc"
	statusResponse.Version.Protocol = 765
	statusResponse.Players.Sample = []sampleEntry{}
	statusResponse.Description.Text = motd
	statusResponse.Favicon = FaviconDataURIPrefix + payloadBase64
	jsonBytes, _ := json.Marshal(statusResponse)
	return jsonBytes
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
