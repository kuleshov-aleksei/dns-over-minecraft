package resolver

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/dns-over-minecraft/dns-over-minecraft/internal/cache"
	"github.com/dns-over-minecraft/dns-over-minecraft/internal/records"
	"github.com/dns-over-minecraft/dns-over-minecraft/internal/upstream"
	"github.com/miekg/dns"
)

type fakeUpstream struct {
	name string
	priority int
	response *dns.Msg
	err  error
	hits int
}

func (fakeUpstreamInstance *fakeUpstream) Name() string { return fakeUpstreamInstance.name }
func (fakeUpstreamInstance *fakeUpstream) Priority() int { return fakeUpstreamInstance.priority }
func (fakeUpstreamInstance *fakeUpstream) Exchange(requestContext context.Context, queryMessage *dns.Msg) (*dns.Msg, error) {
	fakeUpstreamInstance.hits++
	if fakeUpstreamInstance.err != nil {
		return nil, fakeUpstreamInstance.err
	}
	if fakeUpstreamInstance.response != nil {
		return fakeUpstreamInstance.response.Copy(), nil
	}
	return nil, nil
}

func makeQuery(testingInstance *testing.T, name string, queryType uint16, identifier uint16) *dns.Msg {
	testingInstance.Helper()
	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn(name), queryType)
	message.RecursionDesired = true
	message.Id = identifier
	return message
}

func makeResponse(queryMessage *dns.Msg, resourceRecords []dns.RR, responseCode int) *dns.Msg {
	message := new(dns.Msg)
	message.SetReply(queryMessage)
	message.Rcode = responseCode
	message.Answer = resourceRecords
	return message
}

func TestResolver_EmptyQuestion(testingInstance *testing.T) {
	resolverInstance := New(nil, nil, nil)
	queryMessage := new(dns.Msg)
	queryMessage.Id = 999
	queryMessage.RecursionDesired = true
	responseMessage, err := resolverInstance.Resolve(context.Background(), queryMessage)
	if err != nil {
		testingInstance.Fatalf("err %v", err)
	}
	if responseMessage.Rcode != dns.RcodeFormatError {
		testingInstance.Fatalf("want FORMERR, got %d", responseMessage.Rcode)
	}
}

func TestResolver_CacheHit(testingInstance *testing.T) {
	cacheStore := cache.New(10, 5*time.Minute, 30*time.Second)
	recordStore := mustNoRecords(testingInstance)
	fakeUpstreamInstance := &fakeUpstream{name: "fake", priority: 1, response: makeResponse(makeQuery(testingInstance, "example.com", dns.TypeA, 1), nil, dns.RcodeSuccess)}
	upstreamPool := upstream.NewPool([]upstream.Upstream{fakeUpstreamInstance})
	resolverInstance := New(cacheStore, recordStore, upstreamPool)

	queryMessageFirst := makeQuery(testingInstance, "example.com", dns.TypeA, 111)
	answerRecord, _ := dns.NewRR("example.com. 300 IN A 1.1.1.1")
	cachedResponse := makeResponse(queryMessageFirst, []dns.RR{answerRecord}, dns.RcodeSuccess)
	cachedResponse.Id = 0
	cacheStore.Set(queryMessageFirst.Question[0], cachedResponse)

	queryMessageSecond := makeQuery(testingInstance, "example.com", dns.TypeA, 222)
	cachedResult, err := resolverInstance.Resolve(context.Background(), queryMessageSecond)
	if err != nil {
		testingInstance.Fatal(err)
	}
	if cachedResult.Id != 222 {
		testingInstance.Fatalf("Id %d != 222 (cache hit should restore)", cachedResult.Id)
	}
	if !reflect.DeepEqual(cachedResult.Question, queryMessageSecond.Question) {
		testingInstance.Fatalf("Question not restored")
	}
	if len(cachedResult.Answer) != 1 {
		testingInstance.Fatalf("answer len %d", len(cachedResult.Answer))
	}
	if fakeUpstreamInstance.hits != 0 {
		testingInstance.Fatalf("upstream called on cache hit, hits=%d", fakeUpstreamInstance.hits)
	}
	queryMessageThird := makeQuery(testingInstance, "example.com", dns.TypeA, 333)
	cachedResultSecond, _ := resolverInstance.Resolve(context.Background(), queryMessageThird)
	if cachedResultSecond.Id != 333 {
		testingInstance.Fatalf("second cache hit Id mismatch")
	}
	if fakeUpstreamInstance.hits != 0 {
		testingInstance.Fatalf("second hit should be cached")
	}
}

func TestResolver_RecordsAuthoritative(testingInstance *testing.T) {
	cacheStore := cache.New(10, 5*time.Minute, 30*time.Second)
	recordStore, _ := records.New([]records.Record{
		{Name: "mybox.mc", Type: "A", TTL: 60, Values: []string{"10.0.0.5"}},
		{Name: "nodata.mc", Type: "A", TTL: 60, Values: []string{"10.0.0.6"}},
	})
	upstreamPool := upstream.NewPool([]upstream.Upstream{&fakeUpstream{name: "unused", priority: 1, err: errors.New("should not be called")}})
	resolverInstance := New(cacheStore, recordStore, upstreamPool)

	queryMessage := makeQuery(testingInstance, "mybox.mc", dns.TypeA, 100)
	responseMessage, _ := resolverInstance.Resolve(context.Background(), queryMessage)
	if !responseMessage.Authoritative || !responseMessage.RecursionAvailable {
		testingInstance.Fatalf("want Authoritative+RecursionAvailable")
	}
	if len(responseMessage.Answer) != 1 {
		testingInstance.Fatalf("want 1 answer, got %d", len(responseMessage.Answer))
	}
	if responseMessage.Rcode != dns.RcodeSuccess {
		testingInstance.Fatalf("rcode %d", responseMessage.Rcode)
	}
	if _, ok := cacheStore.Get(queryMessage.Question[0]); !ok {
		testingInstance.Fatalf("should cache authoritative answer")
	}

	queryMessageForNODATA := makeQuery(testingInstance, "nodata.mc", dns.TypeTXT, 101)
	responseForNODATA, _ := resolverInstance.Resolve(context.Background(), queryMessageForNODATA)
	if !responseForNODATA.Authoritative {
		testingInstance.Fatalf("NODATA should be authoritative")
	}
	if len(responseForNODATA.Answer) != 0 {
		testingInstance.Fatalf("NODATA should have 0 answers")
	}
	if responseForNODATA.Rcode != dns.RcodeSuccess {
		testingInstance.Fatalf("NODATA rcode should be NOERROR")
	}
	if _, ok := cacheStore.Get(queryMessageForNODATA.Question[0]); !ok {
		testingInstance.Fatalf("NODATA should be cached")
	}
}

func TestResolver_UpstreamFallbackAndCaching(testingInstance *testing.T) {
	cacheStore := cache.New(10, 5*time.Minute, 30*time.Second)
	recordStore, _ := records.New([]records.Record{
		{Name: "local.mc", Type: "A", TTL: 60, Values: []string{"127.0.0.1"}},
	})

	queryMessage := makeQuery(testingInstance, "example.com", dns.TypeA, 200)
	wantedResourceRecord, _ := dns.NewRR("example.com. 300 IN A 8.8.8.8")
	wantedResponse := makeResponse(queryMessage, []dns.RR{wantedResourceRecord}, dns.RcodeSuccess)
	fakeUpstreamOK := &fakeUpstream{name: "ok", priority: 10, response: wantedResponse}
	upstreamPoolOK := upstream.NewPool([]upstream.Upstream{fakeUpstreamOK})
	resolverOK := New(cacheStore, recordStore, upstreamPoolOK)

	resultMessage, err := resolverOK.Resolve(context.Background(), queryMessage)
	if err != nil {
		testingInstance.Fatal(err)
	}
	if len(resultMessage.Answer) != 1 || resultMessage.Answer[0].String() != wantedResourceRecord.String() {
		testingInstance.Fatalf("upstream answer mismatch: %v", resultMessage.Answer)
	}
	if cachedResponse, ok := cacheStore.Get(queryMessage.Question[0]); !ok || len(cachedResponse.Answer) != 1 {
		testingInstance.Fatalf("should cache upstream response")
	}
	fakeUpstreamOK.hits = 0
	queryMessageSecond := makeQuery(testingInstance, "example.com", dns.TypeA, 201)
	resultMessageSecond, _ := resolverOK.Resolve(context.Background(), queryMessageSecond)
	if resultMessageSecond.Id != 201 {
		testingInstance.Fatalf("cache hit Id restore failed")
	}
	if fakeUpstreamOK.hits != 0 {
		testingInstance.Fatalf("second upstream resolve should be cache hit")
	}

	cacheStoreSecond := cache.New(10, 5*time.Minute, 30*time.Second)
	fakeUpstreamFail := &fakeUpstream{name: "fail", priority: 50, err: errors.New("timeout")}
	fakeUpstreamSuccess := &fakeUpstream{name: "succ", priority: 5, response: wantedResponse}
	upstreamPoolFailover := upstream.NewPool([]upstream.Upstream{fakeUpstreamFail, fakeUpstreamSuccess})
	resolverFailover := New(cacheStoreSecond, recordStore, upstreamPoolFailover)
	queryMessageThird := makeQuery(testingInstance, "failover.example.com", dns.TypeA, 300)
	resultMessageThird, _ := resolverFailover.Resolve(context.Background(), queryMessageThird)
	if len(resultMessageThird.Answer) != 1 {
		testingInstance.Fatalf("failover should succeed via second upstream")
	}
	if fakeUpstreamFail.hits != 1 || fakeUpstreamSuccess.hits != 1 {
		testingInstance.Fatalf("failover hits fail=%d succ=%d", fakeUpstreamFail.hits, fakeUpstreamSuccess.hits)
	}

	cacheStoreThird := cache.New(10, 5*time.Minute, 30*time.Second)
	fakeUpstreamError := &fakeUpstream{name: "err", priority: 1, err: errors.New("all down")}
	upstreamPoolAllFail := upstream.NewPool([]upstream.Upstream{fakeUpstreamError})
	resolverAllFail := New(cacheStoreThird, recordStore, upstreamPoolAllFail)
	queryMessageFourth := makeQuery(testingInstance, "down.example.com", dns.TypeA, 400)
	resultMessageFourth, _ := resolverAllFail.Resolve(context.Background(), queryMessageFourth)
	if resultMessageFourth.Rcode != dns.RcodeServerFailure {
		testingInstance.Fatalf("all fail want SERVFAIL, got %d", resultMessageFourth.Rcode)
	}
	if len(resultMessageFourth.Question) != 1 {
		testingInstance.Fatalf("SERVFAIL should preserve question")
	}

	cacheStoreFourth := cache.New(10, 5*time.Minute, 30*time.Second)
	resolverNoPool := New(cacheStoreFourth, recordStore, upstream.NewPool(nil))
	queryMessageFifth := makeQuery(testingInstance, "nopool.example.com", dns.TypeA, 500)
	resultMessageFifth, _ := resolverNoPool.Resolve(context.Background(), queryMessageFifth)
	if resultMessageFifth.Rcode != dns.RcodeServerFailure {
		testingInstance.Fatalf("empty pool want SERVFAIL")
	}
	resolverNilPool := New(cacheStoreFourth, recordStore, nil)
	resultMessageSixth, _ := resolverNilPool.Resolve(context.Background(), queryMessageFifth)
	if resultMessageSixth.Rcode != dns.RcodeServerFailure {
		testingInstance.Fatalf("nil pool want SERVFAIL")
	}

	cacheStoreFifth := cache.New(10, 5*time.Minute, 30*time.Second)
	fakeUpstreamNil := &fakeUpstream{name: "nil", priority: 1, response: nil, err: nil}
	upstreamPoolNil := upstream.NewPool([]upstream.Upstream{fakeUpstreamNil})
	resolverNil := New(cacheStoreFifth, recordStore, upstreamPoolNil)
	queryMessageSixth := makeQuery(testingInstance, "nil.example.com", dns.TypeA, 600)
	resultMessageSeventh, _ := resolverNil.Resolve(context.Background(), queryMessageSixth)
	if resultMessageSeventh.Rcode != dns.RcodeServerFailure {
		testingInstance.Fatalf("nil resp want SERVFAIL, got %d", resultMessageSeventh.Rcode)
	}

	cacheStoreSixth := cache.New(10, 5*time.Minute, 30*time.Second)
	fakeUpstreamForCanceledContext := &fakeUpstream{name: "ctx", priority: 1, response: wantedResponse}
	upstreamPoolForCanceledContext := upstream.NewPool([]upstream.Upstream{fakeUpstreamForCanceledContext})
	resolverForCanceledContext := New(cacheStoreSixth, recordStore, upstreamPoolForCanceledContext)
	backgroundContext, cancelFunc := context.WithCancel(context.Background())
	cancelFunc()
	queryMessageSeventh := makeQuery(testingInstance, "ctx.example.com", dns.TypeA, 700)
	resultMessageEighth, _ := resolverForCanceledContext.Resolve(backgroundContext, queryMessageSeventh)
	if resultMessageEighth.Rcode != dns.RcodeServerFailure {
		testingInstance.Fatalf("canceled ctx want SERVFAIL, got %d", resultMessageEighth.Rcode)
	}
}

func TestResolver_Stats(testingInstance *testing.T) {
	cacheStore := cache.New(10, 5*time.Minute, 30*time.Second)
	recordStore, _ := records.New([]records.Record{
		{Name: "mybox.mc", Type: "A", TTL: 60, Values: []string{"10.0.0.5"}},
	})
	upstreamPool := upstream.NewPool([]upstream.Upstream{&fakeUpstream{name: "fake", priority: 1, response: makeResponse(makeQuery(testingInstance, "other.mc", dns.TypeA, 1), nil, dns.RcodeSuccess)}})
	resolverInstance := New(cacheStore, recordStore, upstreamPool)

	firstQuery := makeQuery(testingInstance, "mybox.mc", dns.TypeA, 1)
	secondQuery := makeQuery(testingInstance, "mybox.mc", dns.TypeA, 2)
	thirdQuery := makeQuery(testingInstance, "other.mc", dns.TypeA, 3)
	_, _ = resolverInstance.Resolve(context.Background(), firstQuery)
	_, _ = resolverInstance.Resolve(context.Background(), secondQuery)
	_, _ = resolverInstance.Resolve(context.Background(), thirdQuery)

	snapshot := resolverInstance.TakeWindow()
	if snapshot.Total != 3 || snapshot.CacheHits != 1 || snapshot.CacheMisses != 2 {
		testingInstance.Fatalf("window got total=%d hits=%d misses=%d, want 3/1/2", snapshot.Total, snapshot.CacheHits, snapshot.CacheMisses)
	}
	afterReset := resolverInstance.TakeWindow()
	if afterReset.Total != 0 || afterReset.CacheHits != 0 || afterReset.CacheMisses != 0 {
		testingInstance.Fatalf("window not reset: %+v", afterReset)
	}

	allTime, lastWindow := resolverInstance.DomainStats(10)
	if len(allTime) != 2 {
		testingInstance.Fatalf("all-time domains len %d, want 2", len(allTime))
	}
	if allTime[0].Name != "mybox.mc." || allTime[0].Count != 2 {
		testingInstance.Fatalf("all-time top should be mybox.mc. (2), got %+v", allTime[0])
	}
	if allTime[1].Name != "other.mc." || allTime[1].Count != 1 {
		testingInstance.Fatalf("all-time second should be other.mc. (1), got %+v", allTime[1])
	}
	if len(lastWindow) != 2 || lastWindow[0].Name != "mybox.mc." || lastWindow[0].Count != 2 {
		testingInstance.Fatalf("last-window should close with mybox.mc. (2) first, got %+v", lastWindow)
	}

	_, _ = resolverInstance.Resolve(context.Background(), makeQuery(testingInstance, "other.mc", dns.TypeA, 4))
	_, lastWindowSecond := resolverInstance.DomainStats(10)
	if len(lastWindowSecond) != 1 || lastWindowSecond[0].Name != "other.mc." || lastWindowSecond[0].Count != 1 {
		testingInstance.Fatalf("last-window should show other.mc. (1), got %+v", lastWindowSecond)
	}
}

func TestResolver_StatsEmptyQuestionCountsAsMiss(testingInstance *testing.T) {
	resolverInstance := New(nil, nil, nil)
	emptyQuery := new(dns.Msg)
	emptyQuery.Id = 999
	emptyQuery.RecursionDesired = true
	_, _ = resolverInstance.Resolve(context.Background(), emptyQuery)

	snapshot := resolverInstance.TakeWindow()
	if snapshot.Total != 1 || snapshot.CacheHits != 0 || snapshot.CacheMisses != 1 {
		testingInstance.Fatalf("empty question should count as total=1 miss=1, got %+v", snapshot)
	}
}

func TestResolver_StatsAllTimePruned(testingInstance *testing.T) {
	resolverInstance := New(nil, nil, nil)
	for index := 0; index < maxTrackedDomains+1; index++ {
		resolverInstance.recordDomain(fmt.Sprintf("d%d.example.com", index))
	}
	resolverInstance.statsMutex.Lock()
	allTimeSize := len(resolverInstance.stats.domainsAll)
	resolverInstance.statsMutex.Unlock()
	if allTimeSize != keepTopDomains {
		testingInstance.Fatalf("all-time map should be pruned to %d, got %d", keepTopDomains, allTimeSize)
	}

	allTime, _ := resolverInstance.DomainStats(keepTopDomains)
	if len(allTime) != keepTopDomains {
		testingInstance.Fatalf("DomainStats should report %d entries, got %d", keepTopDomains, len(allTime))
	}
}

func mustNoRecords(testingInstance *testing.T) *records.Store {
	testingInstance.Helper()
	store, err := records.New(nil)
	if err != nil {
		testingInstance.Fatalf("New empty: %v", err)
	}
	return store
}
