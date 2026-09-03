package client

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/dns-over-minecraft/dns-over-minecraft/internal/cache"
	"github.com/miekg/dns"
)

type fakeQueryFunc struct {
	responses map[string]*dns.Msg
	errs      map[string]error
	calls     []string
}

func (fakeInstance *fakeQueryFunc) Query(serverAddress, suffix string, queryMessage *dns.Msg) (*dns.Msg, error) {
	key := queryMessage.Question[0].Name + "/" + dns.TypeToString[queryMessage.Question[0].Qtype]
	fakeInstance.calls = append(fakeInstance.calls, key)
	if fakeInstance.errs[key] != nil {
		return nil, fakeInstance.errs[key]
	}
	if fakeInstance.responses[key] != nil {
		responseMessage := fakeInstance.responses[key].Copy()
		responseMessage.Id = queryMessage.Id
		responseMessage.Question = queryMessage.Question
		return responseMessage, nil
	}
	return nil, errors.New("no response")
}

func makeQuery(testingInstance *testing.T, name string, queryType uint16, identifier uint16) *dns.Msg {
	testingInstance.Helper()
	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn(name), queryType)
	message.RecursionDesired = true
	message.Id = identifier
	return message
}

func makeAnswer(name string, ipAddress string) dns.RR {
	resourceRecord, _ := dns.NewRR(name + ". 300 IN A " + ipAddress)
	return resourceRecord
}

func TestClient_EmptyQuestion(testingInstance *testing.T) {
	clientInstance := New([]string{"127.0.0.1:25565"}, ".mc", nil, nil)
	queryMessage := new(dns.Msg)
	queryMessage.Id = 999
	queryMessage.RecursionDesired = true
	responseMessage, err := clientInstance.Resolve(context.Background(), queryMessage)
	if err != nil {
		testingInstance.Fatalf("err %v", err)
	}
	if responseMessage.Rcode != dns.RcodeFormatError {
		testingInstance.Fatalf("want FORMERR, got %d", responseMessage.Rcode)
	}
}

func TestClient_CacheHit(testingInstance *testing.T) {
	cacheStore := cache.New(10, 5*time.Minute, 30*time.Second)
	fakeQuery := &fakeQueryFunc{responses: map[string]*dns.Msg{
		"example.com./A": makeQuery(testingInstance, "example.com", dns.TypeA, 1),
	}}
	clientInstance := New([]string{"127.0.0.1:25565"}, ".mc", cacheStore, fakeQuery.Query)

	queryMessageFirst := makeQuery(testingInstance, "example.com", dns.TypeA, 111)
	answerRecord := makeAnswer("example.com", "1.1.1.1")
	queryMessageFirst.Answer = []dns.RR{answerRecord}
	cacheStore.Set(queryMessageFirst.Question[0], queryMessageFirst)

	queryMessageSecond := makeQuery(testingInstance, "example.com", dns.TypeA, 222)
	cachedResult, err := clientInstance.Resolve(context.Background(), queryMessageSecond)
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
	if len(fakeQuery.calls) != 0 {
		testingInstance.Fatalf("queryFunc called on cache hit, calls=%v", fakeQuery.calls)
	}
}

func TestClient_CacheMissStoresAnswer(testingInstance *testing.T) {
	cacheStore := cache.New(10, 5*time.Minute, 30*time.Second)
	queryMessageFirst := makeQuery(testingInstance, "example.com", dns.TypeA, 1)
	queryMessageFirst.Answer = []dns.RR{makeAnswer("example.com", "1.1.1.1")}
	fakeQuery := &fakeQueryFunc{responses: map[string]*dns.Msg{
		"example.com./A": queryMessageFirst,
	}}
	clientInstance := New([]string{"127.0.0.1:25565"}, ".mc", cacheStore, fakeQuery.Query)

	queryMessage := makeQuery(testingInstance, "example.com", dns.TypeA, 222)
	responseMessage, err := clientInstance.Resolve(context.Background(), queryMessage)
	if err != nil {
		testingInstance.Fatal(err)
	}
	if len(responseMessage.Answer) != 1 {
		testingInstance.Fatalf("want 1 answer, got %d", len(responseMessage.Answer))
	}
	if len(fakeQuery.calls) != 1 {
		testingInstance.Fatalf("queryFunc called %d times, want 1", len(fakeQuery.calls))
	}
	if cachedResponse, exists := cacheStore.Get(queryMessage.Question[0]); !exists || len(cachedResponse.Answer) != 1 {
		testingInstance.Fatalf("response should be cached")
	}

	fakeQuery.responses = nil
	queryMessageSecond := makeQuery(testingInstance, "example.com", dns.TypeA, 333)
	cachedResult, _ := clientInstance.Resolve(context.Background(), queryMessageSecond)
	if cachedResult.Id != 333 {
		testingInstance.Fatalf("cache hit Id restore failed")
	}
	if len(fakeQuery.calls) != 1 {
		testingInstance.Fatalf("second resolve should be cache hit, calls=%v", fakeQuery.calls)
	}
}

func TestClient_NXDOMAINNotCached(testingInstance *testing.T) {
	cacheStore := cache.New(10, 5*time.Minute, 30*time.Second)
	nxdomainResponse := makeQuery(testingInstance, "nx.example.com", dns.TypeA, 1)
	nxdomainResponse.Rcode = dns.RcodeNameError
	fakeQuery := &fakeQueryFunc{responses: map[string]*dns.Msg{
		"nx.example.com./A": nxdomainResponse,
	}}
	clientInstance := New([]string{"127.0.0.1:25565"}, ".mc", cacheStore, fakeQuery.Query)

	queryMessage := makeQuery(testingInstance, "nx.example.com", dns.TypeA, 444)
	responseMessage, err := clientInstance.Resolve(context.Background(), queryMessage)
	if err != nil {
		testingInstance.Fatal(err)
	}
	if responseMessage.Rcode != dns.RcodeNameError {
		testingInstance.Fatalf("want NXDOMAIN, got %d", responseMessage.Rcode)
	}
	if _, exists := cacheStore.Get(queryMessage.Question[0]); exists {
		testingInstance.Fatalf("NXDOMAIN should not be cached client-side")
	}
	if len(fakeQuery.calls) != 1 {
		testingInstance.Fatalf("first resolve should hit queryFunc")
	}
	queryMessageSecond := makeQuery(testingInstance, "nx.example.com", dns.TypeA, 555)
	_, _ = clientInstance.Resolve(context.Background(), queryMessageSecond)
	if len(fakeQuery.calls) != 2 {
		testingInstance.Fatalf("NXDOMAIN should be re-queried, calls=%v", fakeQuery.calls)
	}
}

func TestClient_UpstreamErrorReturnsSERVFAIL(testingInstance *testing.T) {
	fakeQuery := &fakeQueryFunc{errs: map[string]error{
		"down.example.com./A": errors.New("connection refused"),
	}}
	clientInstance := New([]string{"127.0.0.1:25565"}, ".mc", nil, fakeQuery.Query)
	queryMessage := makeQuery(testingInstance, "down.example.com", dns.TypeA, 666)
	responseMessage, err := clientInstance.Resolve(context.Background(), queryMessage)
	if err == nil {
		testingInstance.Fatalf("want error")
	}
	if responseMessage.Rcode != dns.RcodeServerFailure {
		testingInstance.Fatalf("want SERVFAIL, got %d", responseMessage.Rcode)
	}
	if len(responseMessage.Question) != 1 {
		testingInstance.Fatalf("SERVFAIL should preserve question")
	}
}

func TestClient_RoundRobin(testingInstance *testing.T) {
	responseMessage := makeQuery(testingInstance, "rr.example.com", dns.TypeA, 1)
	responseMessage.Answer = []dns.RR{makeAnswer("rr.example.com", "1.1.1.1")}
	fakeQuery := &fakeQueryFunc{responses: map[string]*dns.Msg{"rr.example.com./A": responseMessage}}
	clientInstance := New([]string{"server-a:25565", "server-b:25565"}, ".mc", nil, fakeQuery.Query)

	var seenServers []string
	originalQueryFunc := clientInstance.queryFunc
	clientInstance.queryFunc = func(serverAddress, suffix string, queryMessage *dns.Msg) (*dns.Msg, error) {
		seenServers = append(seenServers, serverAddress)
		return originalQueryFunc(serverAddress, suffix, queryMessage)
	}

	for index := 0; index < 4; index++ {
		queryMessage := makeQuery(testingInstance, "rr.example.com", dns.TypeA, uint16(700+index))
		if _, err := clientInstance.Resolve(context.Background(), queryMessage); err != nil {
			testingInstance.Fatal(err)
		}
	}
	want := []string{"server-a:25565", "server-b:25565", "server-a:25565", "server-b:25565"}
	if !reflect.DeepEqual(seenServers, want) {
		testingInstance.Fatalf("round-robin order %v, want %v", seenServers, want)
	}
}

func TestClient_FailoverToHealthyServer(testingInstance *testing.T) {
	healthyResponse := makeQuery(testingInstance, "failover.example.com", dns.TypeA, 1)
	healthyResponse.Answer = []dns.RR{makeAnswer("failover.example.com", "1.1.1.1")}

	unreachableServers := map[string]bool{"server-a:25565": true}
	var seenServers []string
	queryFunc := func(serverAddress, suffix string, queryMessage *dns.Msg) (*dns.Msg, error) {
		seenServers = append(seenServers, serverAddress)
		if unreachableServers[serverAddress] {
			return nil, errors.New("connection refused")
		}
		responseMessage := healthyResponse.Copy()
		responseMessage.Id = queryMessage.Id
		responseMessage.Question = queryMessage.Question
		return responseMessage, nil
	}
	clientInstance := New([]string{"server-a:25565", "server-b:25565", "server-c:25565"}, ".mc", nil, queryFunc)

	queryMessage := makeQuery(testingInstance, "failover.example.com", dns.TypeA, 800)
	responseMessage, err := clientInstance.Resolve(context.Background(), queryMessage)
	if err != nil {
		testingInstance.Fatal(err)
	}
	if responseMessage.Rcode != dns.RcodeSuccess {
		testingInstance.Fatalf("want success, got %d", responseMessage.Rcode)
	}
	if !reflect.DeepEqual(seenServers, []string{"server-a:25565", "server-b:25565"}) {
		testingInstance.Fatalf("failover attempts %v, want [a b]", seenServers)
	}

	seenServers = nil
	queryMessageSecond := makeQuery(testingInstance, "failover.example.com", dns.TypeA, 801)
	if _, err := clientInstance.Resolve(context.Background(), queryMessageSecond); err != nil {
		testingInstance.Fatal(err)
	}
	if !reflect.DeepEqual(seenServers, []string{"server-c:25565"}) {
		testingInstance.Fatalf("rotation after failover %v, want [c]", seenServers)
	}
}

func TestClient_StripsOPTWhenQueryHadNoEDNS(testingInstance *testing.T) {
	queryMessage := makeQuery(testingInstance, "example.com", dns.TypeA, 1)
	responseMessage := new(dns.Msg)
	responseMessage.SetReply(queryMessage)
	responseMessage.SetEdns0(4096, false)
	fakeQuery := &fakeQueryFunc{responses: map[string]*dns.Msg{
		"example.com./A": responseMessage,
	}}
	clientInstance := New([]string{"127.0.0.1:25565"}, ".mc", nil, fakeQuery.Query)

	responseResult, err := clientInstance.Resolve(context.Background(), queryMessage)
	if err != nil {
		testingInstance.Fatal(err)
	}
	if responseResult.IsEdns0() != nil {
		testingInstance.Fatalf("OPT should be stripped when the query had no EDNS")
	}
}

func TestClient_KeepsOPTWhenQueryHadEDNS(testingInstance *testing.T) {
	queryMessage := makeQuery(testingInstance, "example.com", dns.TypeA, 1)
	queryMessage.SetEdns0(4096, false)
	responseMessage := new(dns.Msg)
	responseMessage.SetReply(queryMessage)
	responseMessage.SetEdns0(4096, false)
	fakeQuery := &fakeQueryFunc{responses: map[string]*dns.Msg{
		"example.com./A": responseMessage,
	}}
	clientInstance := New([]string{"127.0.0.1:25565"}, ".mc", nil, fakeQuery.Query)

	responseResult, err := clientInstance.Resolve(context.Background(), queryMessage)
	if err != nil {
		testingInstance.Fatal(err)
	}
	if responseResult.IsEdns0() == nil {
		testingInstance.Fatalf("OPT should be preserved when the query had EDNS")
	}
}

func TestClient_AllServersFail(testingInstance *testing.T) {
	var seenServers []string
	queryFunc := func(serverAddress, suffix string, queryMessage *dns.Msg) (*dns.Msg, error) {
		seenServers = append(seenServers, serverAddress)
		return nil, errors.New("connection refused")
	}
	clientInstance := New([]string{"server-a:25565", "server-b:25565"}, ".mc", nil, queryFunc)

	queryMessage := makeQuery(testingInstance, "down.example.com", dns.TypeA, 900)
	responseMessage, err := clientInstance.Resolve(context.Background(), queryMessage)
	if err == nil {
		testingInstance.Fatal("want error when all servers unreachable")
	}
	if responseMessage.Rcode != dns.RcodeServerFailure {
		testingInstance.Fatalf("want SERVFAIL, got %d", responseMessage.Rcode)
	}
	if len(responseMessage.Question) != 1 {
		testingInstance.Fatalf("SERVFAIL should preserve question")
	}
	if !reflect.DeepEqual(seenServers, []string{"server-a:25565", "server-b:25565"}) {
		testingInstance.Fatalf("attempts %v, want [a b]", seenServers)
	}
}
