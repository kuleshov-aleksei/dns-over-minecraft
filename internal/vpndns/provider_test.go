package vpndns

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestBuildServers_DefaultsPortAndSorts(t *testing.T) {
	sources := []serverSource{
		{addr: "192.168.2.1", priority: 100},
		{addr: "10.0.0.2", port: 5353, priority: -10},
		{addr: "192.168.2.2", priority: 100},
	}
	servers := buildServers(sources)
	want := []Server{
		{Addr: "10.0.0.2:5353", Priority: -10},
		{Addr: "192.168.2.1:53", Priority: 100},
		{Addr: "192.168.2.2:53", Priority: 100},
	}
	if !reflect.DeepEqual(servers, want) {
		t.Fatalf("buildServers = %+v, want %+v", servers, want)
	}
}

func TestPollingProvider_SnapshotAndRefresh(t *testing.T) {
	callCount := 0
	fetch := func() ([]Server, error) {
		callCount++
		if callCount == 1 {
			return []Server{{Addr: "192.168.2.1:53", Priority: 0}}, nil
		}
		return []Server{{Addr: "10.0.0.2:53", Priority: 0}}, nil
	}
	provider := newPollingProvider(fetch)

	if servers := provider.Servers(); len(servers) != 0 {
		t.Fatalf("expected empty before first refresh, got %+v", servers)
	}

	if err := provider.refreshOnce(); err != nil {
		t.Fatalf("refreshOnce: %v", err)
	}
	servers := provider.Servers()
	if len(servers) != 1 || servers[0].Addr != "192.168.2.1:53" {
		t.Fatalf("snapshot = %+v, want one 192.168.2.1", servers)
	}
	// Snapshot must be a copy.
	servers[0].Addr = "mutated"
	if provider.Servers()[0].Addr == "mutated" {
		t.Fatal("Servers must return a copy, not the internal slice")
	}

	if err := provider.refreshOnce(); err != nil {
		t.Fatalf("second refreshOnce: %v", err)
	}
	if got := provider.Servers()[0].Addr; got != "10.0.0.2:53" {
		t.Fatalf("after second refresh got %s", got)
	}
}

func TestPollingProvider_RefreshErrorKeepsSnapshot(t *testing.T) {
	callCount := 0
	fetch := func() ([]Server, error) {
		callCount++
		if callCount == 1 {
			return []Server{{Addr: "192.168.2.1:53", Priority: 0}}, nil
		}
		return nil, errors.New("bus gone")
	}
	provider := newPollingProvider(fetch)
	_ = provider.refreshOnce()
	if err := provider.refreshOnce(); err == nil {
		t.Fatal("expected error from failing refresh")
	}
	if got := provider.Servers()[0].Addr; got != "192.168.2.1:53" {
		t.Fatalf("failed refresh must keep previous snapshot, got %s", got)
	}
}

func TestPollingProvider_StartPolls(t *testing.T) {
	callCount := 0
	fetch := func() ([]Server, error) {
		callCount++
		return []Server{{Addr: "192.168.2.1:53", Priority: 0}}, nil
	}
	provider := newPollingProvider(fetch)

	ctx, cancel := context.WithCancel(context.Background())
	provider.Start(ctx, 1) // 1s poll
	defer cancel()

	deadline := time.Now().Add(3 * time.Second)
	for callCount < 2 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if callCount < 2 {
		t.Fatalf("expected >=2 refreshes from polling, got %d", callCount)
	}
}
