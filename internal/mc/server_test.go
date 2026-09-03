package mc

import (
	"strings"
	"testing"
	"time"

	"github.com/dns-over-minecraft/dns-over-minecraft/internal/resolver"
)

func TestFormatPerformance(testingInstance *testing.T) {
	formatted := formatPerformance(6, 2, 4, 30*time.Second)
	for _, expected := range []string{"6 queries in 30s", "0.20 rps", "cache hit 33.3% miss 66.7%"} {
		if !strings.Contains(formatted, expected) {
			testingInstance.Fatalf("formatPerformance %q missing %q", formatted, expected)
		}
	}
}

func TestFormatTopDomains(testingInstance *testing.T) {
	allTime := []resolver.DomainCount{{Name: "mybox.mc.", Count: 4}, {Name: "example.com.", Count: 2}}
	lastWindow := []resolver.DomainCount{{Name: "other.mc.", Count: 3}}
	formatted := formatTopDomains(allTime, lastWindow, 15*time.Second)
	for _, expected := range []string{"all-time [mybox.mc. (4), example.com. (2)]", "last 15s [other.mc. (3)]"} {
		if !strings.Contains(formatted, expected) {
			testingInstance.Fatalf("formatTopDomains %q missing %q", formatted, expected)
		}
	}
}

func TestFormatDomainListEmpty(testingInstance *testing.T) {
	if formatted := formatDomainList(nil); formatted != "none" {
		testingInstance.Fatalf("empty list should format as none, got %q", formatted)
	}
}