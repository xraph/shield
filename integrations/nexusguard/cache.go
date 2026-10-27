package nexusguard

import (
	"container/list"
	"crypto/sha256"
	"sync"
	"time"

	"github.com/xraph/shield/scan"
)

// defaultVerdictCacheSize is the number of verdicts a guard keeps unless
// WithVerdictCache says otherwise.
const defaultVerdictCacheSize = 10000

// verdictCacheBytes bounds the replacement text a guard's cache holds, so
// 10,000 large tool results cannot pin gigabytes. A verdict whose text alone
// is larger is not cached.
const verdictCacheBytes = 64 << 20

// verdictEntryBytes is what one entry costs besides its text, roughly.
const verdictEntryBytes = 256

// verdictKey identifies a verdict: who scanned what, under which profile
// generation. The text is kept only as its SHA-256.
type verdictKey struct {
	tenant, app, profile, role string
	generation                 uint64
	untrusted                  bool
	sum                        [sha256.Size]byte
}

// verdict is what a scan of one text decided and the text to put in its
// place, when there is one to put.
type verdict struct {
	decision scan.Decision
	text     string
	replace  bool
	scanID   string
	reason   string // set for a block, which is never cached
}

type cacheEntry struct {
	key     verdictKey
	v       verdict
	expires time.Time
	size    int
}

// verdictCache is a least-recently-used cache of verdicts, bounded by entry
// count and by text bytes. It is safe for concurrent use.
type verdictCache struct {
	mu       sync.Mutex
	max      int
	bytes    int
	order    *list.List // front is the most recently used
	elements map[verdictKey]*list.Element
}

// newVerdictCache returns a cache of n verdicts, or nil when n is not
// positive.
func newVerdictCache(n int) *verdictCache {
	if n <= 0 {
		return nil
	}
	return &verdictCache{max: n, order: list.New(), elements: map[verdictKey]*list.Element{}}
}

func (c *verdictCache) get(k verdictKey, now time.Time) (verdict, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.elements[k]
	if !ok {
		return verdict{}, false
	}
	e, ok := el.Value.(*cacheEntry)
	if !ok || !now.Before(e.expires) {
		c.remove(el)
		return verdict{}, false
	}
	c.order.MoveToFront(el)
	return e.v, true
}

// put stores v until expires, evicting the least recently used entries past
// the bounds. A block is never stored.
func (c *verdictCache) put(k verdictKey, v verdict, expires time.Time) {
	size := len(v.text) + verdictEntryBytes
	if v.decision == scan.DecisionBlock || size > verdictCacheBytes {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.elements[k]; ok {
		c.remove(el)
	}
	c.elements[k] = c.order.PushFront(&cacheEntry{key: k, v: v, expires: expires, size: size})
	c.bytes += size
	for c.order.Len() > c.max || c.bytes > verdictCacheBytes {
		c.remove(c.order.Back())
	}
}

func (c *verdictCache) remove(el *list.Element) {
	c.order.Remove(el)
	if e, ok := el.Value.(*cacheEntry); ok {
		delete(c.elements, e.key)
		c.bytes -= e.size
	}
}
