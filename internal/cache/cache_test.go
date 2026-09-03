package cache

import (
	"fmt"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func makeQuestion(testingInstance *testing.T, name string, queryType uint16) dns.Question {
	testingInstance.Helper()
	return dns.Question{Name: dns.Fqdn(name), Qtype: queryType, Qclass: dns.ClassINET}
}

func makeReply(queryMessage *dns.Msg, responseCode int, resourceRecords []dns.RR) *dns.Msg {
	message := new(dns.Msg)
	message.SetReply(queryMessage)
	message.Rcode = responseCode
	message.Answer = resourceRecords
	return message
}

func TestCache_NXDOMAINNotCached(testingInstance *testing.T) {
	cacheStore := New(10, 5*time.Minute, 30*time.Second)
	question := makeQuestion(testingInstance, "nxdomain.example.com", dns.TypeA)
	queryMessage := new(dns.Msg)
	queryMessage.SetQuestion(question.Name, question.Qtype)
	queryMessage.Id = 1
	nxdomainResponse := makeReply(queryMessage, dns.RcodeNameError, nil)

	cacheStore.Set(question, nxdomainResponse)
	if _, exists := cacheStore.Get(question); exists {
		testingInstance.Fatalf("NXDOMAIN should not be cached")
	}

	noErrorResponse := makeReply(queryMessage, dns.RcodeSuccess, nil)
	cacheStore.Set(question, noErrorResponse)
	if _, exists := cacheStore.Get(question); !exists {
		testingInstance.Fatalf("NOERROR response should be cached after NXDOMAIN was not")
	}
}

func TestCache_NilMessageNotCached(testingInstance *testing.T) {
	cacheStore := New(10, 5*time.Minute, 30*time.Second)
	question := makeQuestion(testingInstance, "nil.example.com", dns.TypeA)
	cacheStore.Set(question, nil)
	if _, exists := cacheStore.Get(question); exists {
		testingInstance.Fatalf("nil message should not be cached")
	}
}

func TestCache_NODATACached(testingInstance *testing.T) {
	cacheStore := New(10, 5*time.Minute, 30*time.Second)
	question := makeQuestion(testingInstance, "nodata.example.com", dns.TypeTXT)
	queryMessage := new(dns.Msg)
	queryMessage.SetQuestion(question.Name, question.Qtype)
	queryMessage.Id = 1
	nodataResponse := makeReply(queryMessage, dns.RcodeSuccess, nil)

	cacheStore.Set(question, nodataResponse)
	if _, exists := cacheStore.Get(question); !exists {
		testingInstance.Fatalf("NODATA (NOERROR, no answers) should be cached with negative TTL")
	}
}

func TestCache_MinimumRecordTTLUsed(testingInstance *testing.T) {
	cacheStore := New(10, 5*time.Minute, 30*time.Second)
	question := makeQuestion(testingInstance, "shortttl.example.com", dns.TypeA)
	queryMessage := new(dns.Msg)
	queryMessage.SetQuestion(question.Name, question.Qtype)
	queryMessage.Id = 1
	longRecord, _ := dns.NewRR("shortttl.example.com. 300 IN A 1.1.1.1")
	shortRecord, _ := dns.NewRR("shortttl.example.com. 30 IN A 2.2.2.2")
	response := makeReply(queryMessage, dns.RcodeSuccess, []dns.RR{longRecord, shortRecord})

	cacheStore.Set(question, response)
	cachedMessage, exists := cacheStore.Get(question)
	if !exists {
		testingInstance.Fatalf("response should be cached")
	}
	if len(cachedMessage.Answer) != 2 {
		testingInstance.Fatalf("want 2 answers, got %d", len(cachedMessage.Answer))
	}
	if cachedMessage.Answer[0].Header().Ttl > 300 || cachedMessage.Answer[1].Header().Ttl > 30 {
		testingInstance.Fatalf("cached copy should not exceed original RR TTLs, got %d/%d", cachedMessage.Answer[0].Header().Ttl, cachedMessage.Answer[1].Header().Ttl)
	}

	time.Sleep(31 * time.Millisecond)
	cacheStore.mutex.RLock()
	entry, exists := cacheStore.items[cacheKey(question)]
	cacheStore.mutex.RUnlock()
	if !exists {
		testingInstance.Fatalf("entry should still exist within 30s TTL")
	}
	if !entry.expiresAt.After(time.Now().Add(20 * time.Second)) {
		testingInstance.Fatalf("expiry should use min RR TTL (30s), got %v", entry.expiresAt)
	}
}

func TestCache_ExpiredEntryEvicted(testingInstance *testing.T) {
	cacheStore := New(10, 5*time.Minute, 200*time.Millisecond)
	question := makeQuestion(testingInstance, "expires.example.com", dns.TypeA)
	queryMessage := new(dns.Msg)
	queryMessage.SetQuestion(question.Name, question.Qtype)
	queryMessage.Id = 1
	response := makeReply(queryMessage, dns.RcodeSuccess, nil)

	cacheStore.Set(question, response)
	if _, exists := cacheStore.Get(question); !exists {
		testingInstance.Fatalf("fresh entry should be present")
	}
	time.Sleep(250 * time.Millisecond)
	if _, exists := cacheStore.Get(question); exists {
		testingInstance.Fatalf("expired entry should be gone")
	}
	if _, exists := cacheStore.items[cacheKey(question)]; exists {
		testingInstance.Fatalf("expired entry should be deleted from map")
	}
}

func TestCache_MaxSizeEviction(testingInstance *testing.T) {
	cacheStore := New(3, 5*time.Minute, 30*time.Second)
	for index := 0; index < 5; index++ {
		name := fmt.Sprintf("evict%d.example.com", index)
		question := makeQuestion(testingInstance, name, dns.TypeA)
		queryMessage := new(dns.Msg)
		queryMessage.SetQuestion(question.Name, question.Qtype)
		queryMessage.Id = uint16(index)
		cacheStore.Set(question, makeReply(queryMessage, dns.RcodeSuccess, nil))
	}
	if len(cacheStore.items) > 3 {
		testingInstance.Fatalf("max size exceeded: %d", len(cacheStore.items))
	}
}

func TestCache_TTLDecrementedOnGet(testingInstance *testing.T) {
	cacheStore := New(10, 5*time.Minute, 30*time.Second)
	queryMessage := new(dns.Msg)
	queryMessage.SetQuestion(dns.Fqdn("decrement.example.com"), dns.TypeA)
	queryMessage.Id = 1
	answerRecord, _ := dns.NewRR("decrement.example.com. 300 IN A 1.1.1.1")
	nsRecord, _ := dns.NewRR("decrement.example.com. 100 IN NS ns1.example.com.")
	extraRecord, _ := dns.NewRR("ns1.example.com. 200 IN A 2.2.2.2")

	firstQuestion := makeQuestion(testingInstance, "decrement.example.com", dns.TypeA)
	firstResponse := makeReply(queryMessage, dns.RcodeSuccess, []dns.RR{answerRecord})
	firstResponse.Ns = []dns.RR{nsRecord}
	firstResponse.Extra = []dns.RR{extraRecord}
	cacheStore.Set(firstQuestion, firstResponse)
	cacheStore.mutex.Lock()
	cacheStore.items[cacheKey(firstQuestion)].storedAt = time.Now().Add(-10 * time.Second)
	cacheStore.mutex.Unlock()

	cachedMessage, exists := cacheStore.Get(firstQuestion)
	if !exists {
		testingInstance.Fatalf("entry should still be fresh")
	}
	if cachedMessage.Answer[0].Header().Ttl != 290 {
		testingInstance.Fatalf("answer TTL want 290, got %d", cachedMessage.Answer[0].Header().Ttl)
	}
	if cachedMessage.Ns[0].Header().Ttl != 90 {
		testingInstance.Fatalf("ns TTL want 90, got %d", cachedMessage.Ns[0].Header().Ttl)
	}
	if cachedMessage.Extra[0].Header().Ttl != 190 {
		testingInstance.Fatalf("extra TTL want 190, got %d", cachedMessage.Extra[0].Header().Ttl)
	}

	secondQuestion := makeQuestion(testingInstance, "older.example.com", dns.TypeA)
	secondResponse := makeReply(queryMessage, dns.RcodeSuccess, []dns.RR{answerRecord})
	secondResponse.Ns = []dns.RR{nsRecord}
	cacheStore.Set(secondQuestion, secondResponse)
	cacheStore.mutex.Lock()
	cacheStore.items[cacheKey(secondQuestion)].storedAt = time.Now().Add(-45 * time.Second)
	cacheStore.mutex.Unlock()

	olderCachedMessage, exists := cacheStore.Get(secondQuestion)
	if !exists {
		testingInstance.Fatalf("entry should still be present")
	}
	if olderCachedMessage.Answer[0].Header().Ttl != 255 {
		testingInstance.Fatalf("answer TTL want 255, got %d", olderCachedMessage.Answer[0].Header().Ttl)
	}
	if olderCachedMessage.Ns[0].Header().Ttl != 55 {
		testingInstance.Fatalf("ns TTL want 55, got %d", olderCachedMessage.Ns[0].Header().Ttl)
	}
}

func TestCache_StaleEntryMiss(testingInstance *testing.T) {
	cacheStore := New(10, 5*time.Minute, 30*time.Second)
	question := makeQuestion(testingInstance, "stale.example.com", dns.TypeA)
	queryMessage := new(dns.Msg)
	queryMessage.SetQuestion(question.Name, question.Qtype)
	queryMessage.Id = 1
	record, _ := dns.NewRR("stale.example.com. 60 IN A 1.1.1.1")
	cacheStore.Set(question, makeReply(queryMessage, dns.RcodeSuccess, []dns.RR{record}))

	cacheStore.mutex.Lock()
	cacheStore.items[cacheKey(question)].storedAt = time.Now().Add(-61 * time.Second)
	cacheStore.items[cacheKey(question)].expiresAt = time.Now().Add(-1 * time.Second)
	cacheStore.mutex.Unlock()

	if _, exists := cacheStore.Get(question); exists {
		testingInstance.Fatalf("stale entry should be a miss")
	}
	cacheStore.mutex.RLock()
	_, entryExists := cacheStore.items[cacheKey(question)]
	cacheStore.mutex.RUnlock()
	if entryExists {
		testingInstance.Fatalf("stale entry should be deleted from map")
	}
}

func TestCache_CaseInsensitiveKeys(testingInstance *testing.T) {
	cacheStore := New(10, 5*time.Minute, 30*time.Second)
	mixedCaseQuestion := makeQuestion(testingInstance, "ExAmPlE.CoM", dns.TypeA)
	lowerCaseQuestion := makeQuestion(testingInstance, "example.com", dns.TypeA)
	noTrailingDotQuestion := dns.Question{Name: "EXAMPLE.COM", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	queryMessage := new(dns.Msg)
	queryMessage.SetQuestion(lowerCaseQuestion.Name, lowerCaseQuestion.Qtype)
	queryMessage.Id = 1
	record, _ := dns.NewRR("example.com. 60 IN A 1.1.1.1")

	cacheStore.Set(mixedCaseQuestion, makeReply(queryMessage, dns.RcodeSuccess, []dns.RR{record}))
	if _, exists := cacheStore.Get(lowerCaseQuestion); !exists {
		testingInstance.Fatalf("lowercase lookup should hit mixed-case store")
	}
	if _, exists := cacheStore.Get(noTrailingDotQuestion); !exists {
		testingInstance.Fatalf("no-trailing-dot lookup should hit fqdn store")
	}
}