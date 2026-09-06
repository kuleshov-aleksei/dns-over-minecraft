package mc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

// Frame is VarInt(length) + payload (PacketID + data)
func ReadFrame(reader io.Reader) (packetID int, payload []byte, err error) {
	return ReadFrameLimit(reader, 1<<20)
}

// ReadFrameLimit is ReadFrame with a configurable maximum frame payload size.
// The Minecraft server uses a small limit for its inbound handshake/status/ping
// frames; the client keeps a large limit because DNS responses (base64 favicon
// payloads) can legitimately be many kilobytes.
func ReadFrameLimit(reader io.Reader, maxFrameSize int) (packetID int, payload []byte, err error) {
	length, _, err := ReadVarInt(reader)
	if err != nil {
		return 0, nil, err
	}
	if length <= 0 || length > maxFrameSize {
		return 0, nil, errors.New("frame length out of bounds")
	}
	frameBuffer := make([]byte, length)
	if _, err := io.ReadFull(reader, frameBuffer); err != nil {
		return 0, nil, err
	}
	bufferReader := bytes.NewReader(frameBuffer)
	packetID, _, err = ReadVarInt(bufferReader)
	if err != nil {
		return 0, nil, err
	}
	remainingBytes, _ := io.ReadAll(bufferReader)
	return packetID, remainingBytes, nil
}

func WriteFrame(packetID int, data []byte) []byte {
	packetIDBytes := WriteVarInt(packetID)
	frameLength := len(packetIDBytes) + len(data)
	lengthPrefix := WriteVarInt(frameLength)
	lengthPrefix = append(lengthPrefix, packetIDBytes...)
	lengthPrefix = append(lengthPrefix, data...)
	return lengthPrefix
}

// Handshake packet (client -> server, state 0)
type Handshake struct {
	ProtocolVersion int
	ServerAddress   string
	ServerPort      uint16
	NextState       int
}

func ParseHandshake(payload []byte) (*Handshake, error) {
	payloadReader := bytes.NewReader(payload)
	protocolVersion, _, err := ReadVarInt(payloadReader)
	if err != nil {
		return nil, err
	}
	serverAddress, err := ReadString(payloadReader)
	if err != nil {
		return nil, err
	}
	serverPort, err := ReadUShort(payloadReader)
	if err != nil {
		return nil, err
	}
	nextState, _, err := ReadVarInt(payloadReader)
	if err != nil {
		return nil, err
	}
	return &Handshake{
		ProtocolVersion: protocolVersion,
		ServerAddress:   serverAddress,
		ServerPort:      serverPort,
		NextState:       nextState,
	}, nil
}

func EncodeHandshake(handshake Handshake) []byte {
	var buffer bytes.Buffer
	buffer.Write(WriteVarInt(handshake.ProtocolVersion))
	buffer.Write(WriteString(handshake.ServerAddress))
	buffer.Write(WriteUShort(handshake.ServerPort))
	buffer.Write(WriteVarInt(handshake.NextState))
	return WriteFrame(0x00, buffer.Bytes())
}

func EncodeStatusRequest() []byte {
	return WriteFrame(0x00, []byte{})
}

// EncodeLoginDisconnect builds a clientbound Login Disconnect packet (login
// state 0x00) carrying the given JSON chat reason.
func EncodeLoginDisconnect(reasonJSON string) []byte {
	return WriteFrame(0x00, WriteString(reasonJSON))
}

func DecodePing(payload []byte) (int64, error) {
	if len(payload) != 8 {
		return 0, errors.New("ping payload must be 8 bytes")
	}
	return int64(binary.BigEndian.Uint64(payload)), nil
}

func EncodePing(timestamp int64) []byte {
	timestampBuffer := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBuffer, uint64(timestamp))
	return WriteFrame(0x01, timestampBuffer)
}

func EncodePong(timestamp int64) []byte {
	return EncodePing(timestamp)
}
