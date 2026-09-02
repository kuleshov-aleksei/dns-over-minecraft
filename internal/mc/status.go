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

func EncodeStatusResponse(statusResponse StatusResponse) []byte {
	jsonBytes, _ := json.Marshal(statusResponse)
	return EncodeStatusResponseJSON(jsonBytes)
}

// Alternative helper: build frame from raw JSON bytes (for base64 injection)
// Correct Minecraft framing: Status Response is String (VarInt len + json bytes) inside packet 0x00
func EncodeStatusResponseJSON(rawJSON []byte) []byte {
	packetIDBytes := WriteVarInt(0x00)
	jsonStringBytes := WriteString(string(rawJSON))
	frameBody := append(packetIDBytes, jsonStringBytes...)
	lengthPrefix := WriteVarInt(len(frameBody))
	lengthPrefix = append(lengthPrefix, frameBody...)
	return lengthPrefix
}

func DecodeStatusResponse(payload []byte) (*StatusResponse, error) {
	payloadReader := bytes.NewReader(payload)
	length, bytesRead, err := ReadVarInt(payloadReader)
	if err == nil {
		remainingBytes := make([]byte, length)
		if _, err := payloadReader.Read(remainingBytes); err == nil && payloadReader.Len() == 0 && bytesRead > 0 {
			var statusResponse StatusResponse
			if json.Unmarshal(remainingBytes, &statusResponse) == nil {
				return &statusResponse, nil
			}
		}
		payloadReader = bytes.NewReader(payload)
		if len(payload) > 0 && payload[0] == '{' {
			var statusResponse StatusResponse
			if err := json.Unmarshal(payload, &statusResponse); err == nil {
				return &statusResponse, nil
			}
		}
		payloadReader = bytes.NewReader(payload)
		_, _, _ = ReadVarInt(payloadReader)
		_ = length
		_ = bytesRead
	}
	var statusResponse StatusResponse
	if err := json.Unmarshal(payload, &statusResponse); err != nil {
		return nil, err
	}
	return &statusResponse, nil
}
