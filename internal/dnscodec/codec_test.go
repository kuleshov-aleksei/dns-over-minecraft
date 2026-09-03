package dnscodec

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

var enc32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

func encodeBase32NoPad(buffer []byte) string { return enc32NoPad.EncodeToString(buffer) }

func makeMessage(testingInstance *testing.T, name string, queryType uint16) *dns.Msg {
	testingInstance.Helper()
	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn(name), queryType)
	message.RecursionDesired = true
	message.Id = 1234
	return message
}

func TestEncodeDecodeQuery_Roundtrip(testingInstance *testing.T) {
	testCases := []struct {
		name      string
		queryType uint16
	}{
		{"example.com", dns.TypeA},
		{"example.com", dns.TypeAAAA},
		{"example.com", dns.TypeTXT},
		{"foo.internal.mc", dns.TypeA},
		{"sub.domain.example.org", dns.TypeMX},
		{"a-very-long-subdomain-name-that-still-fits.example.com", dns.TypeA},
		{"singlelabel", dns.TypeA},
		{"test.unknowntld999", dns.TypeA}, // fallback raw
	}
	for _, testCase := range testCases {
		testingInstance.Run(testCase.name+"/"+dns.TypeToString[testCase.queryType], func(innerTesting *testing.T) {
			originalMessage := makeMessage(innerTesting, testCase.name, testCase.queryType)
			encodedQuery, err := EncodeQuery(originalMessage)
			if err != nil {
				innerTesting.Fatalf("EncodeQuery: %v", err)
			}
			if encodedQuery != strings.ToLower(encodedQuery) {
				innerTesting.Fatalf("EncodeQuery not lowercase: %q", encodedQuery)
			}
			if strings.Contains(encodedQuery, "=") {
				innerTesting.Fatalf("EncodeQuery contains padding: %q", encodedQuery)
			}
			decodedMessage, err := DecodeQuery(encodedQuery, "")
			if err != nil {
				innerTesting.Fatalf("DecodeQuery: %v", err)
			}
			if len(decodedMessage.Question) != 1 {
				innerTesting.Fatalf("question len %d", len(decodedMessage.Question))
			}
			question := decodedMessage.Question[0]
			if !strings.EqualFold(question.Name, dns.Fqdn(testCase.name)) {
				innerTesting.Fatalf("name %q != %q", question.Name, dns.Fqdn(testCase.name))
			}
			if question.Qtype != testCase.queryType {
				innerTesting.Fatalf("qtype %d != %d", question.Qtype, testCase.queryType)
			}
			// Minimal format normalizes Id to 0 and RD to true
			if decodedMessage.Id != 0 {
				innerTesting.Fatalf("id %d != 0 (minimal normalizes)", decodedMessage.Id)
			}
			if !decodedMessage.RecursionDesired {
				innerTesting.Fatalf("RD should be true")
			}
		})
	}
}

func TestEncodeCompressesHeader(testingInstance *testing.T) {
	queryMessage := makeMessage(testingInstance, "google.com", dns.TypeA)
	encodedQuery, err := EncodeQuery(queryMessage)
	if err != nil {
		testingInstance.Fatal(err)
	}
	// Old legacy was 45c for google.com (28B). New minimal should be ~13c
	if len(encodedQuery) > 30 {
		innerTestingWarn := testingInstance
		innerTestingWarn.Fatalf("google.com not compressed: len %d want <=30, got %q", len(encodedQuery), encodedQuery)
	}
	// Verify TLD dict used: com -> code 1
	upper := strings.ToUpper(encodedQuery)
	wireBytes, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(upper)
	if len(wireBytes) < 3 || wireBytes[0] != 0xFF || wireBytes[1] != 1 {
		testingInstance.Fatalf("expected magic FF and TLD code 1 for com, got hex %x", wireBytes)
	}
}

func TestTLDDictionaryFallback(testingInstance *testing.T) {
	// Known TLD
	knownMessage := makeMessage(testingInstance, "example.com", dns.TypeA)
	knownEncoded, _ := EncodeQuery(knownMessage)
	knownWire, _ := enc32NoPad.DecodeString(strings.ToUpper(knownEncoded))
	if knownWire[1] == 0 {
		testingInstance.Fatalf("expected dict code for com, got 0")
	}
	// Unknown TLD fallback
	unknownMessage := makeMessage(testingInstance, "example.customtld999", dns.TypeA)
	unknownEncoded, err := EncodeQuery(unknownMessage)
	if err != nil {
		testingInstance.Fatalf("Encode unknown: %v", err)
	}
	upper := strings.ToUpper(unknownEncoded)
	unknownWire, _ := enc32NoPad.DecodeString(upper)
	if unknownWire[1] != 0 {
		testingInstance.Fatalf("expected raw code 0 for unknown TLD, got %d", unknownWire[1])
	}
	decodedUnknown, err := DecodeQuery(unknownEncoded, "")
	if err != nil {
		testingInstance.Fatalf("Decode unknown fallback: %v", err)
	}
	if !strings.EqualFold(decodedUnknown.Question[0].Name, dns.Fqdn("example.customtld999")) {
		testingInstance.Fatalf("fallback roundtrip mismatch %q", decodedUnknown.Question[0].Name)
	}
	// TLD alone
	tldOnlyMessage := makeMessage(testingInstance, "com", dns.TypeA)
	encodedTldOnly, _ := EncodeQuery(tldOnlyMessage)
	decodedTldOnly, err := DecodeQuery(encodedTldOnly, "")
	if err != nil {
		testingInstance.Fatalf("TLD only decode: %v", err)
	}
	if !strings.EqualFold(decodedTldOnly.Question[0].Name, dns.Fqdn("com")) {
		testingInstance.Fatalf("tld only mismatch %q", decodedTldOnly.Question[0].Name)
	}
}

func TestDecodeQuery_SuffixAndChunking(testingInstance *testing.T) {
	queryMessage := makeMessage(testingInstance, "example.com", dns.TypeA)
	encodedQuery, err := EncodeQuery(queryMessage)
	if err != nil {
		testingInstance.Fatal(err)
	}

	suffixes := []string{".mc", ".MC", ".Mc"}
	for _, suffix := range suffixes {
		testingInstance.Run("suffix_"+suffix, func(innerTesting *testing.T) {
			withSuffix := encodedQuery + suffix
			decodedMessage, err := DecodeQuery(withSuffix, suffix)
			if err != nil {
				innerTesting.Fatalf("DecodeQuery with suffix %q: %v", suffix, err)
			}
			if decodedMessage.Question[0].Name != dns.Fqdn("example.com") {
				innerTesting.Fatalf("name mismatch")
			}
			bareQuery := StripSuffix(withSuffix, suffix)
			if bareQuery != encodedQuery {
				innerTesting.Fatalf("StripSuffix %q with %q = %q, want %q", withSuffix, suffix, bareQuery, encodedQuery)
			}
			bareQueryMismatch := StripSuffix(withSuffix, ".other")
			if bareQueryMismatch == encodedQuery {
				innerTesting.Fatalf("StripSuffix should not strip wrong suffix")
			}
		})
	}

	longMessage := new(dns.Msg)
	longName := strings.Repeat("a", 30) + "." + strings.Repeat("b", 30) + ".example.com"
	longMessage.SetQuestion(dns.Fqdn(longName), dns.TypeTXT)
	longMessage.RecursionDesired = true
	longEncodedQuery, err := EncodeQuery(longMessage)
	if err != nil {
		testingInstance.Fatal(err)
	}
	// Minimal should keep longName under 63 most of the time; force very long to test chunking
	if len(longEncodedQuery) <= 63 {
		longNameFallback := strings.Repeat("longlabel-", 10) + strings.Repeat("x", 40) + ".example.com"
		longMessage.SetQuestion(dns.Fqdn(longNameFallback), dns.TypeA)
		longEncodedQuery, _ = EncodeQuery(longMessage)
	}
	var chunkedQuery string
	if len(longEncodedQuery) > 63 {
		var parts []string
		remaining := longEncodedQuery
		for len(remaining) > 63 {
			parts = append(parts, remaining[:63])
			remaining = remaining[63:]
		}
		parts = append(parts, remaining)
		chunkedQuery = strings.Join(parts, ".")
		if !strings.Contains(chunkedQuery, ".") {
			testingInstance.Fatalf("chunked should contain dots")
		}
		decodedMessage, err := DecodeQuery(chunkedQuery, "")
		if err != nil {
			testingInstance.Fatalf("DecodeQuery chunked: %v", err)
		}
		if !strings.EqualFold(decodedMessage.Question[0].Name, dns.Fqdn(longMessage.Question[0].Name)) {
			testingInstance.Fatalf("chunked roundtrip name mismatch: %q vs %q", decodedMessage.Question[0].Name, longMessage.Question[0].Name)
		}
		chunkedWithSuffix := chunkedQuery + ".mc"
		decodedWithSuffix, err := DecodeQuery(chunkedWithSuffix, ".mc")
		if err != nil {
			testingInstance.Fatalf("DecodeQuery chunked+suffix: %v", err)
		}
		if !strings.EqualFold(decodedWithSuffix.Question[0].Name, dns.Fqdn(longMessage.Question[0].Name)) {
			testingInstance.Fatalf("chunked+suffix mismatch")
		}
		bareChunked := StripSuffix(chunkedWithSuffix, ".mc")
		if bareChunked != chunkedQuery {
			testingInstance.Fatalf("StripSuffix chunked: %q != %q", bareChunked, chunkedQuery)
		}
	} else {
		// Even without chunking, verify dot-stripping works
		dotted := longEncodedQuery[:5] + "." + longEncodedQuery[5:]
		decodedDotted, err := DecodeQuery(dotted, "")
		if err != nil {
			testingInstance.Fatalf("Decode dotted minimal: %v", err)
		}
		if !strings.EqualFold(decodedDotted.Question[0].Name, dns.Fqdn(longMessage.Question[0].Name)) {
			testingInstance.Fatalf("dotted mismatch")
		}
	}
}

func TestDecodeQuery_Errors(testingInstance *testing.T) {
	testingInstance.Run("invalid base32", func(innerTesting *testing.T) {
		_, err := DecodeQuery("!!!not-base32!!!", "")
		if err == nil || !strings.Contains(err.Error(), "base32 decode") {
			innerTesting.Fatalf("want base32 decode error, got %v", err)
		}
	})

	testingInstance.Run("invalid magic", func(innerTesting *testing.T) {
		// Encode legacy wire bytes without magic
		legacyWire := []byte{0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 'g', 'o', 'o', 'g', 'l', 'e', 0x00, 0x00, 0x01, 0x00, 0x01}
		encodedLegacy := strings.ToLower(encodeBase32NoPad(legacyWire))
		_, err := DecodeQuery(encodedLegacy, "")
		if err == nil || !strings.Contains(err.Error(), "invalid magic") {
			innerTesting.Fatalf("want invalid magic, got %v", err)
		}
	})

	testingInstance.Run("reserved TLD code", func(innerTesting *testing.T) {
		var buffer []byte
		buffer = append(buffer, magicMinimal)
		buffer = append(buffer, 241) // reserved
		var tmp [binary.MaxVarintLen64]byte
		n := binary.PutUvarint(tmp[:], 1)
		buffer = append(buffer, tmp[:n]...)
		buffer = append(buffer, 0) // name terminator
		encodedReserved := strings.ToLower(encodeBase32NoPad(buffer))
		_, err := DecodeQuery(encodedReserved, "")
		if err == nil || !strings.Contains(err.Error(), "reserved TLD") {
			innerTesting.Fatalf("want reserved TLD error, got %v", err)
		}
	})

	testingInstance.Run("empty string", func(innerTesting *testing.T) {
		_, err := DecodeQuery("", "")
		if err == nil {
			innerTesting.Fatalf("want error for empty, got nil")
		}
	})

	testingInstance.Run("truncated varint", func(innerTesting *testing.T) {
		var buffer []byte
		buffer = append(buffer, magicMinimal, 1, 0xFF, 0xFF) // incomplete varint
		buffer = append(buffer, 0)
		encodedTruncated := strings.ToLower(encodeBase32NoPad(buffer))
		_, err := DecodeQuery(encodedTruncated, "")
		if err == nil {
			innerTesting.Fatalf("want varint error, got nil")
		}
	})

	testingInstance.Run("missing terminator", func(innerTesting *testing.T) {
		var buffer []byte
		buffer = append(buffer, magicMinimal, 1)
		var tmp [binary.MaxVarintLen64]byte
		n := binary.PutUvarint(tmp[:], 1)
		buffer = append(buffer, tmp[:n]...)
		buffer = append(buffer, 3, 'f', 'o', 'o') // missing 0 terminator
		encodedBad := strings.ToLower(encodeBase32NoPad(buffer))
		_, err := DecodeQuery(encodedBad, "")
		if err == nil || !strings.Contains(err.Error(), "0-terminated") {
			innerTesting.Fatalf("want terminator error, got %v", err)
		}
	})

	testingInstance.Run("unsupported qclass", func(innerTesting *testing.T) {
		queryMessage := new(dns.Msg)
		queryMessage.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)
		queryMessage.Question[0].Qclass = dns.ClassCHAOS
		_, err := EncodeQuery(queryMessage)
		if err == nil || !strings.Contains(err.Error(), "qclass") {
			innerTesting.Fatalf("want qclass error, got %v", err)
		}
	})
}

func TestStripSuffix_Edge(testingInstance *testing.T) {
	testCases := []struct {
		address string
		suffix  string
		want    string
	}{
		{"abc.mc", ".mc", "abc"},
		{"abc.MC", ".mc", "abc"},
		{"abc.mc.", ".mc", "abc.mc."},
		{"abc", ".mc", "abc"},
		{"abc", "", "abc"},
		{"a.b.c.mc", ".mc", "a.b.c"},
		{"ABC.mc", ".MC", "ABC"},
		{"", ".mc", ""},
	}
	for _, testCase := range testCases {
		result := StripSuffix(testCase.address, testCase.suffix)
		if result != testCase.want {
			testingInstance.Errorf("StripSuffix(%q,%q)=%q want %q", testCase.address, testCase.suffix, result, testCase.want)
		}
	}
	chunkedQuery := "abc.def.ghi"
	if result := StripSuffix(chunkedQuery+".mc", ".mc"); result != chunkedQuery {
		testingInstance.Errorf("chunked StripSuffix failed: %q", result)
	}
}

func TestEncodeDecodeResponse_Roundtrip(testingInstance *testing.T) {
	queryMessage := makeMessage(testingInstance, "example.com", dns.TypeA)
	responseMessage := new(dns.Msg)
	responseMessage.SetReply(queryMessage)
	responseMessage.Authoritative = true
	resourceRecord, err := dns.NewRR("example.com. 300 IN A 1.2.3.4")
	if err != nil {
		testingInstance.Fatal(err)
	}
	responseMessage.Answer = []dns.RR{resourceRecord}
	responseMessage.Rcode = dns.RcodeSuccess

	encodedResponse, err := EncodeResponse(responseMessage)
	if err != nil {
		testingInstance.Fatalf("EncodeResponse: %v", err)
	}
	if _, err := base64.StdEncoding.DecodeString(encodedResponse); err != nil {
		testingInstance.Fatalf("not valid b64: %v", err)
	}
	decodedResponse, err := DecodeResponse(encodedResponse)
	if err != nil {
		testingInstance.Fatalf("DecodeResponse: %v", err)
	}
	if decodedResponse.Rcode != responseMessage.Rcode {
		testingInstance.Fatalf("rcode %d != %d", decodedResponse.Rcode, responseMessage.Rcode)
	}
	if len(decodedResponse.Answer) != 1 {
		testingInstance.Fatalf("answer len %d", len(decodedResponse.Answer))
	}
	if decodedResponse.Answer[0].String() != resourceRecord.String() {
		testingInstance.Fatalf("rr mismatch %q vs %q", decodedResponse.Answer[0].String(), resourceRecord.String())
	}
	decodedWithWhitespace, err := DecodeResponse("  " + encodedResponse + "\n")
	if err != nil {
		testingInstance.Fatalf("DecodeResponse whitespace: %v", err)
	}
	if len(decodedWithWhitespace.Answer) != 1 {
		testingInstance.Fatalf("whitespace decode answer len")
	}

	nameErrorResponse := new(dns.Msg)
	nameErrorResponse.SetReply(queryMessage)
	nameErrorResponse.Rcode = dns.RcodeNameError
	encodedNameError, _ := EncodeResponse(nameErrorResponse)
	decodedNameError, _ := DecodeResponse(encodedNameError)
	if decodedNameError.Rcode != dns.RcodeNameError {
		testingInstance.Fatalf("NXDOMAIN rcode mismatch")
	}
}

func TestDecodeResponse_Errors(testingInstance *testing.T) {
	if _, err := DecodeResponse(""); err == nil || !strings.Contains(err.Error(), "empty response") {
		testingInstance.Fatalf("want empty response error, got %v", err)
	}
	if _, err := DecodeResponse("   "); err == nil || !strings.Contains(err.Error(), "empty response") {
		testingInstance.Fatalf("want empty for whitespace, got %v", err)
	}
	if _, err := DecodeResponse("!!! not base64 !!!"); err == nil {
		testingInstance.Fatalf("want base64 error")
	}
	badWireBytes := base64.StdEncoding.EncodeToString([]byte("short"))
	if _, err := DecodeResponse(badWireBytes); err == nil {
		testingInstance.Fatalf("want unpack error for bad wire")
	}
}

func TestBuildStatusJSON(testingInstance *testing.T) {
	queryMessage := makeMessage(testingInstance, "example.com", dns.TypeA)
	responseMessage := new(dns.Msg)
	responseMessage.SetReply(queryMessage)
	encodedResponse, _ := EncodeResponse(responseMessage)
	rawJSON := BuildStatusJSON(encodedResponse)
	if !json.Valid(rawJSON) {
		testingInstance.Fatalf("invalid json: %s", rawJSON)
	}
	var rawMessageMap map[string]json.RawMessage
	if err := json.Unmarshal(rawJSON, &rawMessageMap); err != nil {
		testingInstance.Fatalf("unmarshal: %v", err)
	}
	var descriptionStruct struct {
		Text string `json:"text"`
	}
	var topLevel struct {
		Description struct {
			Text string `json:"text"`
		} `json:"description"`
	}
	if err := json.Unmarshal(rawJSON, &topLevel); err != nil {
		testingInstance.Fatalf("unmarshal top: %v", err)
	}
	if topLevel.Description.Text != encodedResponse {
		testingInstance.Fatalf("description.text %q != %q", topLevel.Description.Text, encodedResponse)
	}
	_ = descriptionStruct
}

func TestBuildVanillaStatusJSON(testingInstance *testing.T) {
	rawJSON := BuildVanillaStatusJSON("hello", "1.21.4", 765, 20, 1, []map[string]string{{"name": "a", "id": "00000000-0000-0000-0000-000000000001"}}, "")
	if !json.Valid(rawJSON) {
		testingInstance.Fatalf("invalid json: %s", rawJSON)
	}
	var parsedJSON map[string]interface{}
	if err := json.Unmarshal(rawJSON, &parsedJSON); err != nil {
		testingInstance.Fatalf("unmarshal: %v", err)
	}
	if _, ok := parsedJSON["version"]; !ok {
		testingInstance.Fatalf("missing version")
	}
	if _, ok := parsedJSON["description"]; !ok {
		testingInstance.Fatalf("missing description")
	}
	rawJSONSecond := BuildVanillaStatusJSON("motd", "1.21.4", 765, 20, 0, nil, "")
	var topLevelSecond struct {
		Players struct {
			Sample []interface{} `json:"sample"`
		} `json:"players"`
	}
	if err := json.Unmarshal(rawJSONSecond, &topLevelSecond); err != nil {
		testingInstance.Fatalf("unmarshal2: %v", err)
	}
	if topLevelSecond.Players.Sample == nil {
		testingInstance.Fatalf("sample should be empty slice not nil")
	}
}

func TestBuildErrorResponse(testingInstance *testing.T) {
	queryMessage := makeMessage(testingInstance, "example.com", dns.TypeA)
	responseMessage := BuildErrorResponse(queryMessage, dns.RcodeFormatError)
	if responseMessage.Rcode != dns.RcodeFormatError {
		testingInstance.Fatalf("rcode %d", responseMessage.Rcode)
	}
	if len(responseMessage.Question) != 1 || responseMessage.Question[0].Name != dns.Fqdn("example.com") {
		testingInstance.Fatalf("question not preserved via SetReply")
	}
	if responseMessage.Id != queryMessage.Id {
		testingInstance.Fatalf("id not preserved")
	}
	responseForNilQuery := BuildErrorResponse(nil, dns.RcodeServerFailure)
	if responseForNilQuery.Rcode != dns.RcodeServerFailure {
		testingInstance.Fatalf("nil query rcode")
	}
	if len(responseForNilQuery.Question) != 0 {
		testingInstance.Fatalf("nil query should have no question")
	}
}
