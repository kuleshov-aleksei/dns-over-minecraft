package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefault_LoggingQueriesDisabled(t *testing.T) {
	configuration := Default()
	if configuration.Logging.Queries {
		t.Fatalf("default query logging should be disabled")
	}
}

func TestLoad_LoggingQueriesParsed(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("logging:\n  queries: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configuration, err := Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !configuration.Logging.Queries {
		t.Fatalf("logging.queries should be true")
	}
}