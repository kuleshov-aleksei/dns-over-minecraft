package mc

import (
	"encoding/binary"
	"errors"
	"io"
)

// VarInt is Minecraft's variable-length int (max 5 bytes, 32-bit).
func ReadVarInt(reader io.Reader) (int, int, error) {
	var result int
	var shiftBits uint
	bytesRead := 0
	singleByteBuffer := make([]byte, 1)
	for {
		if bytesRead >= 5 {
			return 0, bytesRead, errors.New("varint too big")
		}
		if _, err := io.ReadFull(reader, singleByteBuffer); err != nil {
			return 0, bytesRead, err
		}
		bytesRead++
		currentByte := singleByteBuffer[0]
		result |= int(currentByte&0x7F) << shiftBits
		shiftBits += 7
		if currentByte&0x80 == 0 {
			break
		}
	}
	return result, bytesRead, nil
}

func WriteVarInt(value int) []byte {
	var buffer [5]byte
	bytesWritten := binary.PutUvarint(buffer[:], uint64(uint32(value)))
	return buffer[:bytesWritten]
}

func ReadString(reader io.Reader) (string, error) {
	length, _, err := ReadVarInt(reader)
	if err != nil {
		return "", err
	}
	if length < 0 || length > 255*4 {
		return "", errors.New("string length out of bounds")
	}
	stringBuffer := make([]byte, length)
	if _, err := io.ReadFull(reader, stringBuffer); err != nil {
		return "", err
	}
	return string(stringBuffer), nil
}

func WriteString(value string) []byte {
	valueBytes := []byte(value)
	lengthPrefix := WriteVarInt(len(valueBytes))
	return append(lengthPrefix, valueBytes...)
}

func ReadUShort(reader io.Reader) (uint16, error) {
	ushortBuffer := make([]byte, 2)
	if _, err := io.ReadFull(reader, ushortBuffer); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(ushortBuffer), nil
}

func WriteUShort(value uint16) []byte {
	ushortBuffer := make([]byte, 2)
	binary.BigEndian.PutUint16(ushortBuffer, value)
	return ushortBuffer
}
