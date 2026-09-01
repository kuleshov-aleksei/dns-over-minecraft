package mc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

// Frame is VarInt(length) + payload (PacketID + data)
func ReadFrame(r io.Reader) (packetID int, payload []byte, err error) {
	length, _, err := ReadVarInt(r)
	if err != nil {
		return 0, nil, err
	}
	if length <= 0 || length > 1<<20 { // 1MB cap
		return 0, nil, errors.New("frame length out of bounds")
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, err
	}
	br := bytes.NewReader(buf)
	packetID, _, err = ReadVarInt(br)
	if err != nil {
		return 0, nil, err
	}
	remaining, _ := io.ReadAll(br)
	return packetID, remaining, nil
}

func WriteFrame(packetID int, data []byte) []byte {
	pid := WriteVarInt(packetID)
	frameLen := len(pid) + len(data)
	out := WriteVarInt(frameLen)
	out = append(out, pid...)
	out = append(out, data...)
	return out
}

// Handshake packet (client -> server, state 0)
type Handshake struct {
	ProtocolVersion int
	ServerAddress   string
	ServerPort      uint16
	NextState       int
}

func ParseHandshake(payload []byte) (*Handshake, error) {
	r := bytes.NewReader(payload)
	proto, _, err := ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	addr, err := ReadString(r)
	if err != nil {
		return nil, err
	}
	port, err := ReadUShort(r)
	if err != nil {
		return nil, err
	}
	nextState, _, err := ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	return &Handshake{
		ProtocolVersion: proto,
		ServerAddress:   addr,
		ServerPort:      port,
		NextState:       nextState,
	}, nil
}

func EncodeHandshake(h Handshake) []byte {
	var buf bytes.Buffer
	buf.Write(WriteVarInt(h.ProtocolVersion))
	buf.Write(WriteString(h.ServerAddress))
	buf.Write(WriteUShort(h.ServerPort))
	buf.Write(WriteVarInt(h.NextState))
	return WriteFrame(0x00, buf.Bytes())
}

func EncodeStatusRequest() []byte {
	return WriteFrame(0x00, []byte{})
}

func DecodePing(payload []byte) (int64, error) {
	if len(payload) != 8 {
		return 0, errors.New("ping payload must be 8 bytes")
	}
	return int64(binary.BigEndian.Uint64(payload)), nil
}

func EncodePing(ts int64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(ts))
	return WriteFrame(0x01, buf)
}

func EncodePong(ts int64) []byte {
	return EncodePing(ts)
}
