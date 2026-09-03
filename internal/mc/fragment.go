package mc

import (
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var fragmentTimeout = 5 * time.Second

const (
	minFragmentPieces = 2
)

type fragmentKey struct {
	clientIP string
	nonce    string
}

// fragmentSet accumulates pieces of one fragmented query. Assembly completes
// exactly once (guarded by started); the resolved result is stored so every
// fragment connection of the query can receive it. lastSeen is only touched
// under the assembler mutex, so it is not guarded by set.mutex.
type fragmentSet struct {
	mutex        sync.Mutex
	pieces       map[int]string
	total        int
	started      bool
	done         bool
	response     *dns.Msg
	resolveError error
	resultReady  chan struct{}
	lastSeen     time.Time
}

type fragmentAssembler struct {
	mutex sync.Mutex
	sets  map[fragmentKey]*fragmentSet
}

func newFragmentAssembler() *fragmentAssembler {
	return &fragmentAssembler{sets: make(map[fragmentKey]*fragmentSet)}
}

// add stores a fragment piece and reports whether this call completed the set
// (i.e. is responsible for resolving and publishing the result).
func (assembler *fragmentAssembler) add(key fragmentKey, index, total int, piece string) (*fragmentSet, bool) {
	assembler.mutex.Lock()
	assembler.purgeLocked()
	set := assembler.sets[key]
	if set == nil {
		set = &fragmentSet{
			pieces:      make(map[int]string),
			resultReady: make(chan struct{}),
		}
		assembler.sets[key] = set
	}
	set.lastSeen = time.Now()
	assembler.mutex.Unlock()

	completer := false
	set.mutex.Lock()
	if set.total == 0 {
		set.total = total
	}
	set.pieces[index] = piece
	if !set.started && !set.done && len(set.pieces) == set.total {
		set.started = true
		completer = true
	}
	set.mutex.Unlock()
	return set, completer
}

func (set *fragmentSet) reassemble() string {
	set.mutex.Lock()
	defer set.mutex.Unlock()
	var builder strings.Builder
	for index := 1; index <= set.total; index++ {
		builder.WriteString(set.pieces[index])
	}
	return builder.String()
}

func (set *fragmentSet) storeResult(response *dns.Msg, resolveError error) {
	set.mutex.Lock()
	set.response = response
	set.resolveError = resolveError
	set.done = true
	set.mutex.Unlock()
	close(set.resultReady)
}

func (set *fragmentSet) waitResult() (*dns.Msg, error) {
	select {
	case <-set.resultReady:
	case <-time.After(fragmentTimeout):
		return nil, errors.New("fragment assembly timeout")
	}
	set.mutex.Lock()
	defer set.mutex.Unlock()
	return set.response, set.resolveError
}

func (assembler *fragmentAssembler) purgeLocked() {
	cutoff := time.Now().Add(-2 * fragmentTimeout)
	for key, set := range assembler.sets {
		if set.lastSeen.Before(cutoff) {
			delete(assembler.sets, key)
		}
	}
}
