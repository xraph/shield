// Package textnorm folds text into one canonical form for pattern matching
// and maps every folded byte back to the original text, so a detector can
// match the folded form and still redact the exact original bytes.
package textnorm

import (
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// Text is a string and its folded form. Folded is NFKC normalised and lower
// case, has zero-width and bidi control runes removed, and has every
// whitespace run collapsed to one space. Build it with Fold.
type Text struct {
	// Original is the text as given.
	Original string
	// Folded is the canonical form that patterns run on.
	Folded string

	// starts and ends hold, for each byte of Folded, the original byte range
	// of the normalisation segment it came from.
	starts, ends []int32
	// hidden holds the original byte offset of every removed rune.
	hidden []int
}

// IsHidden reports whether r is a zero-width or bidi control rune that Fold
// removes: U+200B to U+200F, U+2060, U+FEFF, U+202A to U+202E and U+2066 to
// U+2069.
func IsHidden(r rune) bool {
	switch {
	case r >= 0x200B && r <= 0x200F,
		r == 0x2060,
		r == 0xFEFF,
		r >= 0x202A && r <= 0x202E,
		r >= 0x2066 && r <= 0x2069:
		return true
	}
	return false
}

// Fold builds the folded form of s with its offset map.
func Fold(s string) Text {
	t := Text{Original: s}
	kept, removed := stripHidden(s)
	for _, r := range removed {
		t.hidden = append(t.hidden, r.at)
	}

	folded := make([]byte, 0, len(kept))
	t.starts = make([]int32, 0, len(kept))
	t.ends = make([]int32, 0, len(kept))
	shift := shifter{removed: removed}
	inSpace := false
	var buf []byte
	for p := 0; p < len(kept); {
		// An ASCII byte not followed by a combining mark is its own NFKC
		// segment and folds without the normaliser.
		ascii := kept[p] < utf8.RuneSelf && (p+1 == len(kept) || kept[p+1] < utf8.RuneSelf)
		n := 1
		if !ascii {
			n = norm.NFKC.NextBoundaryInString(kept[p:], true)
			if n <= 0 {
				n = len(kept) - p
			}
		}
		start := offset(p + shift.upTo(p))
		end := offset(p + n + shift.upTo(p+n-1))
		seg := kept[p : p+n]
		p += n

		if ascii {
			buf = append(buf[:0], seg[0])
		} else {
			buf = norm.NFKC.AppendString(buf[:0], seg)
		}
		for _, r := range string(buf) {
			if unicode.IsSpace(r) {
				if inSpace {
					t.ends[len(t.ends)-1] = end
					continue
				}
				inSpace = true
				r = ' '
			} else {
				inSpace = false
				r = unicode.ToLower(r)
			}
			before := len(folded)
			folded = utf8.AppendRune(folded, r)
			for range len(folded) - before {
				t.starts = append(t.starts, start)
				t.ends = append(t.ends, end)
			}
		}
	}
	t.Folded = string(folded)
	return t
}

// removal is one hidden rune Fold dropped: its original offset, its size, and
// the offset in the kept text where it would have been.
type removal struct {
	at, size, kept int
}

// stripHidden removes hidden runes from s. Hidden runes cannot then split a
// word or block NFKC composition. Text without any is returned as is.
func stripHidden(s string) (string, []removal) {
	var removed []removal
	var kept []byte
	last := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if IsHidden(r) {
			if kept == nil {
				kept = make([]byte, 0, len(s))
			}
			kept = append(kept, s[last:i]...)
			removed = append(removed, removal{at: i, size: size, kept: len(kept)})
			last = i + size
		}
		i += size
	}
	if removed == nil {
		return s, nil
	}
	return string(append(kept, s[last:]...)), removed
}

// shifter maps kept offsets back to original ones. Calls must not go
// backwards.
type shifter struct {
	removed []removal
	next    int
	shift   int
}

// upTo returns the bytes removed at or before kept offset k.
func (s *shifter) upTo(k int) int {
	for s.next < len(s.removed) && s.removed[s.next].kept <= k {
		s.shift += s.removed[s.next].size
		s.next++
	}
	return s.shift
}

// Span maps the folded byte range [start, end) to the original byte range it
// came from. Offsets are clamped to Folded. A Text not built by Fold maps any
// range to the whole original.
func (t Text) Span(start, end int) (origStart, origEnd int) {
	n := len(t.Folded)
	if len(t.starts) != n || len(t.ends) != n {
		return 0, len(t.Original)
	}
	start = min(max(start, 0), n)
	end = min(max(end, start), n)
	if start == n {
		return len(t.Original), len(t.Original)
	}
	origStart = int(t.starts[start])
	if end == start {
		return origStart, origStart
	}
	return origStart, int(t.ends[end-1])
}

// Lines widens the original byte range [start, end) to the whole lines it
// touches: from just after the preceding '\n' to just before the next one.
// A range that ends with a '\n' does not pull in the following line.
func (t Text) Lines(start, end int) (lineStart, lineEnd int) {
	s := t.Original
	start = min(max(start, 0), len(s))
	end = min(max(end, start), len(s))
	if end > start && s[end-1] == '\n' {
		end--
	}
	if end > start && s[start] == '\n' {
		start++
	}
	lineStart = strings.LastIndexByte(s[:start], '\n') + 1
	lineEnd = len(s)
	if i := strings.IndexByte(s[end:], '\n'); i >= 0 {
		lineEnd = end + i
	}
	return lineStart, lineEnd
}

// Hidden returns the number of zero-width and bidi control runes Fold removed.
func (t Text) Hidden() int {
	return len(t.hidden)
}

// HiddenAt returns the original byte offset of every removed rune, in order.
func (t Text) HiddenAt() []int {
	return slices.Clone(t.hidden)
}

// offset narrows a byte offset for the per-byte maps, which halves their
// memory. Scans are capped far below 2 GiB, so it cannot overflow.
func offset(i int) int32 {
	return int32(i) //nolint:gosec // G115: scan input is capped far below 2 GiB
}
