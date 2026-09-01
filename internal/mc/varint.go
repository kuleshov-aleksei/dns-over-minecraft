package mc

import (
	"encoding/binary"
	"errors"
	"io"
)

// VarInt is Minecraft's variable-length int (max 5 bytes, 32-bit).
func ReadVarInt(r io.Reader) (int, int, error) {
	var result int
	var shift uint
	bytesRead := 0
	buf := make([]byte, 1)
	for {
		if bytesRead >= 5 {
			return 0, bytesRead, errors.New("varint too big")
		}
		if _, err := io.ReadFull(r, buf); err != nil {
			return 0, bytesRead, err
		}
		bytesRead++
		b := buf[0]
		result |= int(b&0x7F) << shift
		shift += 7
		if b&0x80 == 0 {
			break
		}
	}
	return result, bytesRead, nil
}

func WriteVarInt(v int) []byte {
	var buf [5]byte
	n := binary.PutUvarint(buf[:], uint64(uint32(v)))
	return buf[:n]
}

func ReadString(r io.Reader) (string, error) {
	length, _, err := ReadVarInt(r)
	if err != nil {
		return "", err
	}
	if length < 0 || length > 255*4 { // allow up to 255*4 bytes for utf8
		return "", errors.New("string length out of bounds")
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

func WriteString(s string) []byte {
	b := []byte(s)
	out := WriteVarInt(len(b))
	return append(out, b...)
}

func ReadUShort(r io.Reader) (uint16, error) {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(buf), nil
}

func WriteUShort(v uint16) []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, v)
	return buf
}
