package mc

import (
	"bytes"
	"encoding/json"
)

// StatusResponse is server -> client JSON.
type StatusResponse struct {
	Version struct {
		Name     string `json:"name"`
		Protocol int    `json:"protocol"`
	} `json:"version"`
	Players struct {
		Max    int `json:"max"`
		Online int `json:"online"`
		Sample []struct {
			Name string `json:"name"`
			ID   string `json:"id"`
		} `json:"sample"`
	} `json:"players"`
	Description struct {
		Text string `json:"text"`
	} `json:"description"`
	Favicon string `json:"favicon,omitempty"`
}

func EncodeStatusResponse(sr StatusResponse) []byte {
	jsonBytes, _ := json.Marshal(sr)
	return EncodeStatusResponseJSON(jsonBytes)
}

// Alternative helper: build frame from raw JSON bytes (for base64 injection)
// Correct Minecraft framing: Status Response is String (VarInt len + json bytes) inside packet 0x00
func EncodeStatusResponseJSON(rawJSON []byte) []byte {
	pid := WriteVarInt(0x00)
	str := WriteString(string(rawJSON)) // VarInt(len) + json
	body := append(pid, str...)
	out := WriteVarInt(len(body))
	out = append(out, body...)
	return out
}

func DecodeStatusResponse(payload []byte) (*StatusResponse, error) {
	// payload is packetID already stripped by ReadFrame, so it's VarInt(len(json)) + json or just json
	// Some impls send json directly without inner VarInt length; handle both.
	r := bytes.NewReader(payload)
	// Try to read VarInt length prefix
	length, n, err := ReadVarInt(r)
	if err == nil {
		// if remaining bytes == length, it's prefixed
		remaining := make([]byte, length)
		if _, err := r.Read(remaining); err == nil && r.Len() == 0 && n > 0 {
			var sr StatusResponse
			if json.Unmarshal(remaining, &sr) == nil {
				return &sr, nil
			}
		}
		// fallback: payload is json with length prefix we already consumed incorrectly - reset
		r = bytes.NewReader(payload)
		// peek if first byte is '{'
		if len(payload) > 0 && payload[0] == '{' {
			var sr StatusResponse
			if err := json.Unmarshal(payload, &sr); err == nil {
				return &sr, nil
			}
		}
		// try reading again with length
		r = bytes.NewReader(payload)
		_, _, _ = ReadVarInt(r)
		_ = length
		_ = n
	}
	var sr StatusResponse
	if err := json.Unmarshal(payload, &sr); err != nil {
		return nil, err
	}
	return &sr, nil
}
