package records

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func mustStore(testingInstance *testing.T, records []Record) *Store {
	testingInstance.Helper()
	store, err := New(records)
	if err != nil {
		testingInstance.Fatalf("New: %v", err)
	}
	return store
}

func TestNew_DefaultTTLAndInvalidType(testingInstance *testing.T) {
	store := mustStore(testingInstance, []Record{
		{Name: "example.com", Type: "A", TTL: 0, Values: []string{"1.2.3.4"}},
		{Name: "example.com", Type: "INVALID", TTL: 300, Values: []string{"1.2.3.4"}},
		{Name: "bad.example.com", Type: "A", TTL: 300, Values: []string{"not-an-ip"}},
	})
	question := dns.Question{Name: dns.Fqdn("example.com"), Qtype: dns.TypeA}
	resourceRecords, authoritative := store.Lookup(question)
	if !authoritative || len(resourceRecords) != 1 {
		testingInstance.Fatalf("want 1 RR authoritative, got auth=%v len=%d", authoritative, len(resourceRecords))
	}
	if resourceRecords[0].Header().Ttl != 300 {
		testingInstance.Fatalf("TTL %d != 300", resourceRecords[0].Header().Ttl)
	}
	questionForTXT := dns.Question{Name: dns.Fqdn("example.com"), Qtype: dns.TypeTXT}
	resourceRecordsForTXT, authoritativeForTXT := store.Lookup(questionForTXT)
	if !authoritativeForTXT {
		testingInstance.Fatalf("want authoritative for NODATA")
	}
	if len(resourceRecordsForTXT) != 0 {
		testingInstance.Fatalf("want 0 RRs for missing TXT, got %d", len(resourceRecordsForTXT))
	}
	questionForBad := dns.Question{Name: dns.Fqdn("bad.example.com"), Qtype: dns.TypeA}
	_, authoritativeForBad := store.Lookup(questionForBad)
	if authoritativeForBad {
		testingInstance.Fatalf("bad RR should not create authoritative entry")
	}
}

func TestLookup_ExactCaseInsensitiveAndCopy(testingInstance *testing.T) {
	store := mustStore(testingInstance, []Record{
		{Name: "Example.COM", Type: "A", TTL: 60, Values: []string{"1.1.1.1", "2.2.2.2"}},
	})
	question := dns.Question{Name: "EXAMPLE.com.", Qtype: dns.TypeA}
	resourceRecords, authoritative := store.Lookup(question)
	if !authoritative || len(resourceRecords) != 2 {
		testingInstance.Fatalf("want 2 RRs, got auth=%v len=%d", authoritative, len(resourceRecords))
	}
	resourceRecords[0].Header().Name = "mutated."
	resourceRecordsSecond, _ := store.Lookup(question)
	if strings.EqualFold(resourceRecordsSecond[0].Header().Name, "mutated.") {
		testingInstance.Fatalf("Lookup should return copy, store was mutated")
	}
	if resourceRecords[0].Header().Ttl != 60 {
		testingInstance.Fatalf("TTL mismatch")
	}
}

func TestLookup_CNAMEFallbackAndNODATA(testingInstance *testing.T) {
	store := mustStore(testingInstance, []Record{
		{Name: "cname.example.com", Type: "CNAME", TTL: 300, Values: []string{"target.example.com."}},
		{Name: "nodata.example.com", Type: "A", TTL: 300, Values: []string{"1.1.1.1"}},
	})
	questionForCNAMEFallback := dns.Question{Name: dns.Fqdn("cname.example.com"), Qtype: dns.TypeA}
	resourceRecords, authoritative := store.Lookup(questionForCNAMEFallback)
	if !authoritative || len(resourceRecords) != 1 {
		testingInstance.Fatalf("CNAME fallback: auth=%v len=%d", authoritative, len(resourceRecords))
	}
	if resourceRecords[0].Header().Rrtype != dns.TypeCNAME {
		testingInstance.Fatalf("want CNAME, got %d", resourceRecords[0].Header().Rrtype)
	}
	questionForDirectCNAME := dns.Question{Name: dns.Fqdn("cname.example.com"), Qtype: dns.TypeCNAME}
	resourceRecordsDirect, authoritativeDirect := store.Lookup(questionForDirectCNAME)
	if !authoritativeDirect || len(resourceRecordsDirect) != 1 {
		testingInstance.Fatalf("direct CNAME query failed")
	}
	questionForNODATA := dns.Question{Name: dns.Fqdn("nodata.example.com"), Qtype: dns.TypeTXT}
	resourceRecordsNODATA, authoritativeNODATA := store.Lookup(questionForNODATA)
	if !authoritativeNODATA {
		testingInstance.Fatalf("want authoritative NODATA")
	}
	if len(resourceRecordsNODATA) != 0 {
		testingInstance.Fatalf("want 0 RRs for NODATA, got %d", len(resourceRecordsNODATA))
	}
	questionForMissing := dns.Question{Name: dns.Fqdn("missing.example.com"), Qtype: dns.TypeA}
	_, authoritativeForMissing := store.Lookup(questionForMissing)
	if authoritativeForMissing {
		testingInstance.Fatalf("missing should be non-authoritative")
	}
}

func TestLookup_Wildcard(testingInstance *testing.T) {
	store := mustStore(testingInstance, []Record{
		{Name: "*.internal.mc", Type: "A", TTL: 100, Values: []string{"10.0.0.1"}},
		{Name: "*.internal.mc", Type: "TXT", TTL: 100, Values: []string{"\"hello\""}},
		{Name: "exact.internal.mc", Type: "A", TTL: 100, Values: []string{"9.9.9.9"}},
	})

	for _, name := range []string{"foo.internal.mc", "a.b.internal.mc", "FOO.internal.mc"} {
		question := dns.Question{Name: dns.Fqdn(name), Qtype: dns.TypeA}
		resourceRecords, authoritative := store.Lookup(question)
		if !authoritative || len(resourceRecords) != 1 {
			testingInstance.Fatalf("wildcard %q: auth=%v len=%d", name, authoritative, len(resourceRecords))
		}
		if !strings.EqualFold(resourceRecords[0].Header().Name, dns.Fqdn(name)) {
			testingInstance.Fatalf("wildcard owner rewrite %q != %q", resourceRecords[0].Header().Name, dns.Fqdn(name))
		}
		if resourceRecords[0].Header().Rrtype != dns.TypeA {
			testingInstance.Fatalf("qtype mismatch")
		}
	}

	questionForExact := dns.Question{Name: dns.Fqdn("exact.internal.mc"), Qtype: dns.TypeA}
	resourceRecordsForExact, _ := store.Lookup(questionForExact)
	if resourceRecordsForExact[0].String() != "exact.internal.mc.\t100\tIN\tA\t9.9.9.9" {
		testingInstance.Fatalf("exact should win over wildcard, got %q", resourceRecordsForExact[0].String())
	}

	questionForTXTWildcard := dns.Question{Name: dns.Fqdn("foo.internal.mc"), Qtype: dns.TypeTXT}
	resourceRecordsForTXT, authoritativeForTXT := store.Lookup(questionForTXTWildcard)
	if !authoritativeForTXT || len(resourceRecordsForTXT) != 1 || resourceRecordsForTXT[0].Header().Rrtype != dns.TypeTXT {
		testingInstance.Fatalf("wildcard TXT failed: auth=%v len=%d", authoritativeForTXT, len(resourceRecordsForTXT))
	}
	questionForAAAA := dns.Question{Name: dns.Fqdn("foo.internal.mc"), Qtype: dns.TypeAAAA}
	_, authoritativeForAAAA := store.Lookup(questionForAAAA)
	if authoritativeForAAAA {
		testingInstance.Fatalf("no AAAA wildcard -> should be non-authoritative, not NODATA")
	}

	storeForCNAMEWildcard := mustStore(testingInstance, []Record{
		{Name: "*.cname.mc", Type: "CNAME", TTL: 300, Values: []string{"target.example.com."}},
	})
	questionForCNAMEWildcard := dns.Question{Name: dns.Fqdn("sub.cname.mc"), Qtype: dns.TypeA}
	resourceRecordsForCNAMEWildcard, authoritativeForCNAMEWildcard := storeForCNAMEWildcard.Lookup(questionForCNAMEWildcard)
	if !authoritativeForCNAMEWildcard || len(resourceRecordsForCNAMEWildcard) != 1 || resourceRecordsForCNAMEWildcard[0].Header().Rrtype != dns.TypeCNAME {
		testingInstance.Fatalf("wildcard CNAME fallback failed")
	}
}
