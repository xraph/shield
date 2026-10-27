package perception

import (
	"slices"
	"strconv"
	"strings"
)

// Span is a byte range of the original text and the placeholder that
// replaces it.
type Span struct {
	Start       int    `json:"start"`
	End         int    `json:"end"`
	Placeholder string `json:"placeholder"`
}

// Placeholders turns matches into redaction spans "[TYPE_n]", sorted by
// Start. n counts per Type from 1 in reading order, and every match of the
// same value and Type within one call shares its n. A Match built by hand
// carries no value and gets its own n.
func Placeholders(matches []Match) []Span {
	if len(matches) == 0 {
		return nil
	}
	order := slices.Clone(matches)
	slices.SortStableFunc(order, func(a, b Match) int {
		if a.Start != b.Start {
			return a.Start - b.Start
		}
		return a.End - b.End
	})
	type key struct {
		typ   string
		value uint64
	}
	numbers := map[key]int{}
	counts := map[string]int{}
	spans := make([]Span, 0, len(order))
	for _, m := range order {
		n, ok := 0, false
		if m.value != 0 {
			n, ok = numbers[key{m.Type, m.value}]
		}
		if !ok {
			counts[m.Type]++
			n = counts[m.Type]
			if m.value != 0 {
				numbers[key{m.Type, m.value}] = n
			}
		}
		spans = append(spans, Span{Start: m.Start, End: m.End, Placeholder: "[" + m.Type + "_" + strconv.Itoa(n) + "]"})
	}
	return spans
}

// Apply replaces every span of text with its placeholder. Offsets are
// clamped to text and empty spans are skipped. Overlapping spans merge into
// one, and the earliest-starting span's placeholder wins (the first given
// on a tie).
func Apply(text string, spans []Span) string {
	if len(spans) == 0 {
		return text
	}
	order := make([]Span, 0, len(spans))
	for _, s := range spans {
		s.Start = min(max(s.Start, 0), len(text))
		s.End = min(max(s.End, 0), len(text))
		if s.Start < s.End {
			order = append(order, s)
		}
	}
	slices.SortStableFunc(order, func(a, b Span) int { return a.Start - b.Start })
	var b strings.Builder
	b.Grow(len(text))
	last := 0
	for i := 0; i < len(order); {
		cur := order[i]
		end := cur.End
		i++
		for i < len(order) && order[i].Start < end {
			end = max(end, order[i].End)
			i++
		}
		b.WriteString(text[last:cur.Start])
		b.WriteString(cur.Placeholder)
		last = end
	}
	b.WriteString(text[last:])
	return b.String()
}
