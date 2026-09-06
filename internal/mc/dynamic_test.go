package mc

import (
	"testing"
	"time"
)

func fixedUTCTime(testedInstance *testing.T, hour, minute int) time.Time {
	testedInstance.Helper()
	return time.Date(2026, time.September, 6, hour, minute, 0, 0, time.UTC)
}

func TestDynamicOnlinePlayers_PeakAndDip(testedInstance *testing.T) {
	serverInstance := &Server{MaxPlayers: 20, OnlinePlayers: 6}

	if got := serverInstance.dynamicOnlinePlayers(fixedUTCTime(testedInstance, 18, 0)); got != 6 {
		testedInstance.Fatalf("peak at 18:00 = %d, want 6", got)
	}
	if got := serverInstance.dynamicOnlinePlayers(fixedUTCTime(testedInstance, 6, 0)); got != 3 {
		testedInstance.Fatalf("dip at 06:00 = %d, want 3", got)
	}
}

func TestDynamicOnlinePlayers_WithinBounds(testedInstance *testing.T) {
	serverInstance := &Server{MaxPlayers: 20, OnlinePlayers: 6}
	for hour := 0; hour < 24; hour++ {
		for minute := 0; minute < 60; minute += 15 {
			online := serverInstance.dynamicOnlinePlayers(fixedUTCTime(testedInstance, hour, minute))
			if online < 0 || online > 20 {
				testedInstance.Fatalf("online %d at %02d:%02d out of bounds [0,20]", online, hour, minute)
			}
			if online > serverInstance.OnlinePlayers {
				testedInstance.Fatalf("online %d at %02d:%02d exceeds peak %d", online, hour, minute, serverInstance.OnlinePlayers)
			}
		}
	}
}

func TestDynamicOnlinePlayers_ClampsToMaxPlayers(testedInstance *testing.T) {
	serverInstance := &Server{MaxPlayers: 5, OnlinePlayers: 10}
	if got := serverInstance.dynamicOnlinePlayers(fixedUTCTime(testedInstance, 18, 0)); got != 5 {
		testedInstance.Fatalf("peak clamped to maxPlayers: got %d, want 5", got)
	}
	if got := serverInstance.dynamicOnlinePlayers(fixedUTCTime(testedInstance, 6, 0)); got != 3 {
		testedInstance.Fatalf("dip for clamped peak: got %d, want 3", got)
	}
}

func TestCapSample(testedInstance *testing.T) {
	sample := []map[string]string{
		{"name": "A", "id": "1"},
		{"name": "B", "id": "2"},
		{"name": "C", "id": "3"},
	}
	if got := capSample(sample, 2); len(got) != 2 || got[0]["name"] != "A" || got[1]["name"] != "B" {
		testedInstance.Fatalf("capSample to 2 = %v, want first two entries", got)
	}
	if got := capSample(sample, 0); len(got) != 0 {
		testedInstance.Fatalf("capSample to 0 = %v, want empty", got)
	}
	if got := capSample(sample, 5); len(got) != 3 {
		testedInstance.Fatalf("capSample above length = %v, want full sample", got)
	}
}
