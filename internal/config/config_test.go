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