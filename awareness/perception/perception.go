// Package perception holds the deterministic awareness detectors: personal
// data, secrets and topics, plus the placeholders that redact what they
// find.
//
// Detectors run on the text with its invisible runes removed (see
// textnorm.Strip), so a zero-width space cannot split a token, and report
// original byte offsets that cover any such runes. A Match never holds the
// text it matched: it carries the detector, a placeholder type, offsets, a
// score and an opaque fingerprint that lets Placeholders give a repeated
// value the same number.
package perception

import (
	"fmt"
	"hash/maphash"
	"regexp"
	"slices"
	"strings"

	"github.com/xraph/shield/internal/textnorm"
)

// Match is one detection. Start and End are original byte offsets; for a
// pattern with a named group "secret" they cover that group only. Type is
// the upper-case placeholder stem, such as "EMAIL" or "GITHUB_TOKEN".
type Match struct {
	Detector string  `json:"detector"`
	Type     string  `json:"type"`
	Start    int     `json:"start"`
	End      int     `json:"end"`
	Score    float64 `json:"score"`

	// value fingerprints the matched text with a per-process seed, so equal
	// values can share a placeholder. Zero means unknown.
	value uint64
}

// String formats the exported fields only, so the value fingerprint never
// reaches a log.
func (m Match) String() string {
	return fmt.Sprintf("{Detector:%s Type:%s Start:%d End:%d Score:%v}", m.Detector, m.Type, m.Start, m.End, m.Score)
}

// GoString formats the exported fields only, for %#v.
func (m Match) GoString() string {
	return fmt.Sprintf("perception.Match{Detector:%q, Type:%q, Start:%d, End:%d, Score:%v}", m.Detector, m.Type, m.Start, m.End, m.Score)
}

// seed keys the value fingerprints. It is random per process and never
// leaves it.
var seed = maphash.MakeSeed()

// redactGroup names the capture group that narrows a match to the part to
// redact.
const redactGroup = "secret"

// Custom runs caller patterns over text and reports every non-empty match
// as detector name, type name upper-cased with other runes as '_', score 1.
// A pattern with a named group "secret" reports that group only.
func Custom(text, name string, patterns []*regexp.Regexp) []Match {
	c := newCollector(text)
	typ := typeName(name)
	for _, re := range patterns {
		c.regexp(re, name, typ, 1)
	}
	return c.result()
}

// typeName turns a detector name into a placeholder stem: upper case, with
// every rune other than A to Z and 0 to 9 replaced by '_'.
func typeName(name string) string {
	if name == "" {
		return "CUSTOM"
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r - 'a' + 'A'
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		}
		return '_'
	}, name)
}

// collector gathers matches over the visible form of one text.
type collector struct {
	v       textnorm.Visible
	s       string // v.Text
	matches []Match
}

func newCollector(text string) *collector {
	v := textnorm.Strip(text)
	return &collector{v: v, s: v.Text}
}

// add records a match over the visible range [start, end).
func (c *collector) add(detector, typ string, score float64, start, end int) {
	if start >= end {
		return
	}
	h := maphash.String(seed, c.s[start:end])
	if h == 0 {
		h = 1
	}
	os, oe := c.v.Span(start, end)
	c.matches = append(c.matches, Match{Detector: detector, Type: typ, Start: os, End: oe, Score: score, value: h})
}

// regexp records every non-empty match of re, narrowed to its "secret"
// group when it has one that took part.
func (c *collector) regexp(re *regexp.Regexp, detector, typ string, score float64) {
	if re == nil {
		return
	}
	group := re.SubexpIndex(redactGroup)
	for _, loc := range re.FindAllStringSubmatchIndex(c.s, -1) {
		start, end := loc[0], loc[1]
		if group > 0 && loc[2*group] >= 0 {
			start, end = loc[2*group], loc[2*group+1]
		}
		c.add(detector, typ, score, start, end)
	}
}

// result resolves overlaps and returns the matches in reading order.
func (c *collector) result() []Match {
	return dropOverlaps(c.matches)
}

// dropOverlaps keeps, wherever matches overlap, the highest-scoring one
// (then the longest, then the earliest), and drops every match that
// overlaps a kept one. The result is sorted by Start. Matches that touch
// no other pass through, and each overlapping cluster is resolved on its
// own, so the work stays linear in the text.
func dropOverlaps(ms []Match) []Match {
	if len(ms) < 2 {
		return ms
	}
	slices.SortStableFunc(ms, func(a, b Match) int {
		if a.Start != b.Start {
			return a.Start - b.Start
		}
		return b.End - a.End
	})
	out := ms[:0:0]
	for i := 0; i < len(ms); {
		j, end := i+1, ms[i].End
		for j < len(ms) && ms[j].Start < end {
			end = max(end, ms[j].End)
			j++
		}
		if j == i+1 {
			out = append(out, ms[i])
		} else {
			out = append(out, resolveCluster(ms[i:j], ms[i].Start, end)...)
		}
		i = j
	}
	return out
}

// resolveCluster picks the matches to keep from one run of overlapping
// matches spanning [from, to).
func resolveCluster(cluster []Match, from, to int) []Match {
	order := slices.Clone(cluster)
	slices.SortStableFunc(order, func(a, b Match) int {
		switch {
		case a.Score != b.Score:
			if a.Score > b.Score {
				return -1
			}
			return 1
		case a.End-a.Start != b.End-b.Start:
			return (b.End - b.Start) - (a.End - a.Start)
		}
		return a.Start - b.Start
	})
	taken := make([]bool, to-from)
	kept := make([]Match, 0, len(order))
	for _, m := range order {
		if slices.Contains(taken[m.Start-from:m.End-from], true) {
			continue
		}
		for k := m.Start; k < m.End; k++ {
			taken[k-from] = true
		}
		kept = append(kept, m)
	}
	slices.SortFunc(kept, func(a, b Match) int { return a.Start - b.Start })
	return kept
}

// enabled reports whether detector name is on: every name in all when
// names is empty, else only the names listed.
func enabled(names []string, name string) bool {
	return len(names) == 0 || slices.Contains(names, name)
}

// isAlnum reports whether b is an ASCII letter or digit.
func isAlnum(b byte) bool {
	return isDigit(b) || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

// isDigit reports whether b is an ASCII digit.
func isDigit(b byte) bool {
	return b >= '0' && b <= '9'
}

// at returns s[i], or 0 when i is out of range.
func at(s string, i int) byte {
	if i < 0 || i >= len(s) {
		return 0
	}
	return s[i]
}
