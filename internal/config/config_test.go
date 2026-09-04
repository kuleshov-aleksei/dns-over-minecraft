package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefault_LoggingDisabled(t *testing.T) {
	configuration := Default()
	if configuration.Logging.Queries {
		t.Fatalf("default query logging should be disabled")
	}
	if configuration.Logging.Performance {
		t.Fatalf("default performance logging should be disabled")
	}
	if configuration.Logging.Analytics {
		t.Fatalf("default analytics logging should be disabled")
	}
	if configuration.Logging.Interval != 30*time.Second {
		t.Fatalf("default logging interval should be 30s, got %s", configuration.Logging.Interval)
	}
}

func TestLoad_LoggingParsed(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")
	yamlContent := "logging:\n  queries: true\n  performance: true\n  analytics: true\n  interval: 15s\n"
	if err := os.WriteFile(configPath, []byte(yamlContent), 0o600); err != nil {
		t.Fatal(err)
	}
	configuration, err := Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !configuration.Logging.Queries {
		t.Fatalf("logging.queries should be true")
	}
	if !configuration.Logging.Performance {
		t.Fatalf("logging.performance should be true")
	}
	if !configuration.Logging.Analytics {
		t.Fatalf("logging.analytics should be true")
	}
	if configuration.Logging.Interval != 15*time.Second {
		t.Fatalf("logging.interval should be 15s, got %s", configuration.Logging.Interval)
	}
}

func TestLoad_CacheDisabledParsed(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")
	yamlContent := "cache:\n  disabled: true\nclient:\n  cache:\n    disabled: true\n"
	if err := os.WriteFile(configPath, []byte(yamlContent), 0o600); err != nil {
		t.Fatal(err)
	}
	configuration, err := Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !configuration.Cache.Disabled {
		t.Fatalf("cache.disabled should be true")
	}
	if !configuration.Client.Cache.Disabled {
		t.Fatalf("client.cache.disabled should be true")
	}
}

func TestLoad_LoggingIntervalDefaults(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("logging:\n  performance: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configuration, err := Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if configuration.Logging.Interval != 30*time.Second {
		t.Fatalf("empty logging.interval should default to 30s, got %s", configuration.Logging.Interval)
	}
}

func TestDefault_SecurityHardening(t *testing.T) {
	configuration := Default()
	if configuration.Security.Passphrase != "" {
		t.Fatalf("default passphrase should be empty, got %q", configuration.Security.Passphrase)
	}
	if configuration.Security.RateLimit != 100 {
		t.Fatalf("default rate limit should be 100, got %d", configuration.Security.RateLimit)
	}
	if configuration.Security.MaxConnections != 1024 {
		t.Fatalf("default max connections should be 1024, got %d", configuration.Security.MaxConnections)
	}
	if configuration.Security.MaxFrameSize != 4096 {
		t.Fatalf("default max frame size should be 4096, got %d", configuration.Security.MaxFrameSize)
	}
}

func TestLoad_SecurityParsed(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")
	yamlContent := "security:\n  passphrase: s3cr3t\n  rateLimit: 250\n  maxConnections: 64\n  maxFrameSize: 8192\nclient:\n  passphrase: s3cr3t\n"
	if err := os.WriteFile(configPath, []byte(yamlContent), 0o600); err != nil {
		t.Fatal(err)
	}
	configuration, err := Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if configuration.Security.Passphrase != "s3cr3t" {
		t.Fatalf("security.passphrase should be s3cr3t, got %q", configuration.Security.Passphrase)
	}
	if configuration.Security.RateLimit != 250 {
		t.Fatalf("security.rateLimit should be 250, got %d", configuration.Security.RateLimit)
	}
	if configuration.Security.MaxConnections != 64 {
		t.Fatalf("security.maxConnections should be 64, got %d", configuration.Security.MaxConnections)
	}
	if configuration.Security.MaxFrameSize != 8192 {
		t.Fatalf("security.maxFrameSize should be 8192, got %d", configuration.Security.MaxFrameSize)
	}
	if configuration.Client.Passphrase != "s3cr3t" {
		t.Fatalf("client.passphrase should be s3cr3t, got %q", configuration.Client.Passphrase)
	}
}
