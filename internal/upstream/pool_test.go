package upstream

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type fakeUpstream struct {
	name     string
	priority int
	response *dns.Msg
	err      error
	delay    time.Duration
	hits     int
}

func (fakeUpstreamInstance *fakeUpstream) Name() string { return fakeUpstreamInstance.name }
func (fakeUpstreamInstance *fakeUpstream) Priority() int { return fakeUpstreamInstance.priority }
func (fakeUpstreamInstance *fakeUpstream) Exchange(requestContext context.Context, queryMessage *dns.Msg) (*dns.Msg, error) {
	fakeUpstreamInstance.hits++
	if fakeUpstreamInstance.delay > 0 {
		time.Sleep(fakeUpstreamInstance.delay)
	}
	return fakeUpstreamInstance.response, fakeUpstreamInstance.err
}

func makeMessage(testingInstance *testing.T, name string) *dns.Msg {
	testingInstance.Helper()
	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn(name), dns.TypeA)
	return message
}

func TestNewPool_SortingReal(testingInstance *testing.T) {
	upstreamB := &fakeUpstream{name: "b", priority: 10}
	upstreamA := &fakeUpstream{name: "a", priority: 10}
	upstreamCHighPriority := &fakeUpstream{name: "c", priority: 5}
	upstreamZHighPriority := &fakeUpstream{name: "z", priority: 5}
	upstreamPool := NewPool([]Upstream{upstreamB, upstreamA, upstreamCHighPriority, upstreamZHighPriority})
	sortedUpstreams := upstreamPool.List()
	if sortedUpstreams[0].Priority() != 10 || sortedUpstreams[0].Name() != "a" {
		testingInstance.Fatalf("0: got %s %d", sortedUpstreams[0].Name(), sortedUpstreams[0].Priority())
	}
	if sortedUpstreams[1].Priority() != 10 || sortedUpstreams[1].Name() != "b" {
		testingInstance.Fatalf("1: got %s %d", sortedUpstreams[1].Name(), sortedUpstreams[1].Priority())
	}
	if sortedUpstreams[2].Priority() != 5 || sortedUpstreams[2].Name() != "c" {
		testingInstance.Fatalf("2: got %s %d", sortedUpstreams[2].Name(), sortedUpstreams[2].Priority())
	}
	if sortedUpstreams[3].Priority() != 5 || sortedUpstreams[3].Name() != "z" {
		testingInstance.Fatalf("3: got %s %d", sortedUpstreams[3].Name(), sortedUpstreams[3].Priority())
	}
}

func TestPool_Exchange_Fallback(testingInstance *testing.T) {
	queryMessage := makeMessage(testingInstance, "example.com")
	wantedResponse := makeMessage(testingInstance, "example.com")
	wantedResponse.SetReply(queryMessage)
	failingUpstream := &fakeUpstream{name: "fail", priority: 50, err: errors.New("down")}
	successUpstream := &fakeUpstream{name: "ok", priority: 5, response: wantedResponse}
	upstreamPool := NewPool([]Upstream{successUpstream, failingUpstream})
	resultMessage, err := upstreamPool.Exchange(context.Background(), queryMessage)
	if err != nil {
		testingInstance.Fatalf("want success, err %v", err)
	}
	if resultMessage == nil || len(resultMessage.Question) != 1 {
		testingInstance.Fatalf("want response")
	}
	if failingUpstream.hits != 1 || successUpstream.hits != 1 {
		testingInstance.Fatalf("hits fail=%d ok=%d", failingUpstream.hits, successUpstream.hits)
	}

	failingUpstreamFirst := &fakeUpstream{name: "f1", priority: 50, err: errors.New("e1")}
	failingUpstreamSecond := &fakeUpstream{name: "f2", priority: 5, err: errors.New("e2")}
	upstreamPoolSecond := NewPool([]Upstream{failingUpstreamFirst, failingUpstreamSecond})
	_, errSecond := upstreamPoolSecond.Exchange(context.Background(), queryMessage)
	if errSecond == nil || errSecond.Error() != "e2" {
		testingInstance.Fatalf("want lastErr e2, got %v", errSecond)
	}

	nilUpstreamFirst := &fakeUpstream{name: "n1", priority: 1, response: nil, err: nil}
	nilUpstreamSecond := &fakeUpstream{name: "n2", priority: 2, response: nil, err: nil}
	upstreamPoolThird := NewPool([]Upstream{nilUpstreamFirst, nilUpstreamSecond})
	_, errThird := upstreamPoolThird.Exchange(context.Background(), queryMessage)
	if !errors.Is(errThird, context.DeadlineExceeded) {
		testingInstance.Fatalf("want DeadlineExceeded, got %v", errThird)
	}

	backgroundContext, cancelFunc := context.WithCancel(context.Background())
	cancelFunc()
	upstreamForCanceledContext := &fakeUpstream{name: "f3", priority: 1, response: wantedResponse}
	upstreamPoolFourth := NewPool([]Upstream{upstreamForCanceledContext})
	_, errFourth := upstreamPoolFourth.Exchange(backgroundContext, queryMessage)
	if !errors.Is(errFourth, context.Canceled) {
		testingInstance.Fatalf("want Canceled, got %v", errFourth)
	}
	if upstreamForCanceledContext.hits != 0 {
		testingInstance.Fatalf("canceled should not call upstream")
	}

	emptyPool := NewPool(nil)
	_, errFifth := emptyPool.Exchange(context.Background(), queryMessage)
	if !errors.Is(errFifth, context.DeadlineExceeded) {
		testingInstance.Fatalf("empty pool want DeadlineExceeded, got %v", errFifth)
	}
}

func TestPool_EWMAOrdersSamePriority(testingInstance *testing.T) {
	queryMessage := makeMessage(testingInstance, "example.com")
	wantedResponse := makeMessage(testingInstance, "example.com")
	wantedResponse.SetReply(queryMessage)
	slowUpstream := &fakeUpstream{name: "a-slow", priority: 5, response: wantedResponse, delay: 15 * time.Millisecond}
	fastUpstream := &fakeUpstream{name: "z-fast", priority: 5, response: wantedResponse, delay: time.Millisecond}
	upstreamPool := NewPool([]Upstream{slowUpstream, fastUpstream})

	if upstreamPool.List()[0].Name() != "a-slow" {
		testingInstance.Fatalf("initial order should be name-ascending (a-slow), got %s", upstreamPool.List()[0].Name())
	}
	for index := 0; index < 8; index++ {
		if _, err := upstreamPool.Exchange(context.Background(), queryMessage); err != nil {
			testingInstance.Fatalf("exchange err: %v", err)
		}
	}
	orderedUpstreams := upstreamPool.List()
	if orderedUpstreams[0].Name() != "z-fast" {
		testingInstance.Fatalf("faster upstream should be tried first, got %s", orderedUpstreams[0].Name())
	}
}

func TestPool_EWMAKeepsPriorityTiers(testingInstance *testing.T) {
	queryMessage := makeMessage(testingInstance, "example.com")
	wantedResponse := makeMessage(testingInstance, "example.com")
	wantedResponse.SetReply(queryMessage)
	highPrioritySlowUpstream := &fakeUpstream{name: "high", priority: 10, response: wantedResponse, delay: 20 * time.Millisecond}
	lowPriorityFastUpstream := &fakeUpstream{name: "low", priority: 5, response: wantedResponse, delay: time.Millisecond}
	upstreamPool := NewPool([]Upstream{lowPriorityFastUpstream, highPrioritySlowUpstream})

	for index := 0; index < 8; index++ {
		if _, err := upstreamPool.Exchange(context.Background(), queryMessage); err != nil {
			testingInstance.Fatalf("exchange err: %v", err)
		}
	}
	orderedUpstreams := upstreamPool.List()
	if orderedUpstreams[0].Name() != "high" {
		testingInstance.Fatalf("higher priority tier must be tried first despite being slower, got %s", orderedUpstreams[0].Name())
	}
}
