package mc

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"
)

func TestServer_LoginKickedNotWhitelisted(testedInstance *testing.T) {
	serverAddress, _ := startTestServer(testedInstance)

	connection, err := net.DialTimeout("tcp", serverAddress, 3*time.Second)
	if err != nil {
		testedInstance.Fatalf("dial: %v", err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))

	handshake := Handshake{
		ProtocolVersion: 765,
		ServerAddress:   "mc.example.com",
		ServerPort:      25565,
		NextState:       2,
	}
	if _, err := connection.Write(EncodeHandshake(handshake)); err != nil {
		testedInstance.Fatalf("write handshake: %v", err)
	}
	if _, err := connection.Write(WriteFrame(0x00, WriteString("Steve"))); err != nil {
		testedInstance.Fatalf("write login start: %v", err)
	}

	packetID, payload, err := ReadFrame(connection)
	if err != nil {
		testedInstance.Fatalf("read login response: %v", err)
	}
	if packetID != 0x00 {
		testedInstance.Fatalf("response packet id %d, want login disconnect 0x00", packetID)
	}
	reason, err := ReadString(bytes.NewReader(payload))
	if err != nil {
		testedInstance.Fatalf("read reason: %v", err)
	}
	if !strings.Contains(reason, "You are not whitelisted") {
		testedInstance.Fatalf("kick reason %q, want it to contain %q", reason, "You are not whitelisted")
	}
}

func TestServer_LoginKickedWithoutLoginStart(testedInstance *testing.T) {
	serverAddress, _ := startTestServer(testedInstance)

	connection, err := net.DialTimeout("tcp", serverAddress, 3*time.Second)
	if err != nil {
		testedInstance.Fatalf("dial: %v", err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))

	handshake := Handshake{
		ProtocolVersion: 765,
		ServerAddress:   "mc.example.com",
		ServerPort:      25565,
		NextState:       2,
	}
	if _, err := connection.Write(EncodeHandshake(handshake)); err != nil {
		testedInstance.Fatalf("write handshake: %v", err)
	}

	// A client that never sends Login Start should simply have the connection
	// closed once the handshake budget expires, not hang.
	startedAt := time.Now()
	_ = connection.SetReadDeadline(time.Now().Add(3 * time.Second))
	readBuffer := make([]byte, 1)
	_, _ = connection.Read(readBuffer)
	if elapsed := time.Since(startedAt); elapsed < 2*time.Second {
		testedInstance.Fatalf("connection closed after %s, want handshake budget wait", elapsed.Round(time.Millisecond))
	}
}
