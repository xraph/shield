// Package textnorm folds text into one canonical form for pattern matching
// and maps every folded byte back to the original text, so a detector can
// match the folded form and still redact the exact original bytes.
package textnorm

import (
	"slices"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// Text is a string and its folded form. Folded is NFKC normalised and lower
// case, has invisible runes removed (see IsHidden), has Cyrillic and Greek
// lookalikes inside Latin words replaced by their Latin letters, and has
// every whitespace run collapsed to one space. Build it with Fold.
type Text struct {
	// Original is the text as given.
	Original string
	// Folded is the canonical form that patterns run on.
	Folded string

	// starts and ends hold, for each byte of Folded, the original byte range
	// of the normalisation segment it came from.
	starts, ends []int32
	// hidden holds the original byte offset of every removed rune that hid
	// something (see Hidden).
	hidden []int
	// newlines indexes the '\n' offsets of Original on first use.
	newlines *newlineIndex
}

// IsHidden reports whether r is an invisible rune that Fold removes:
// zero-width and joiner characters (U+200B to U+200F, U+2060 to U+2064,
// U+FEFF, U+180E, U+034F), the soft hyphen U+00AD, bidi controls (U+202A to
// U+202E, U+2066 to U+2069), tag characters (U+E0000 to U+E007F) and the
// supplementary variation selectors (U+E0100 to U+E01EF).
func IsHidden(r rune) bool {
	switch {
	case r >= 0x200B && r <= 0x200F,
		r >= 0x2060 && r <= 0x2064,
		r == 0xFEFF,
		r == 0x180E,
		r == 0x034F,
		r == 0x00AD,
		r >= 0x202A && r <= 0x202E,
		r >= 0x2066 && r <= 0x2069,
		r >= 0xE0000 && r <= 0xE007F,
		r >= 0xE0100 && r <= 0xE01EF:
		return true
	}
	return false
}

// Fold builds the folded form of s with its offset map.
func Fold(s string) Text {
	t := Text{Original: s, newlines: &newlineIndex{}}
	kept, removed := stripHidden(s)
	for _, r := range removed {
		if r.counted {
			t.hidden = append(t.hidden, r.at)
		}
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
			buf = norm.NFKC.AppendString(buf[:0], stripMarks(seg))
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
	folded, t.starts, t.ends = foldConfusables(folded, t.starts, t.ends)
	t.Folded = string(folded)
	return t
}

// removal is one invisible rune Fold dropped: its original offset, its size,
// the offset in the kept text where it would have been, and whether it hid
// something rather than doing a legitimate job.
type removal struct {
	at, size, kept int
	counted        bool
}

// stripHidden removes invisible runes from s, so they cannot split a word or
// block NFKC composition, and classifies each one. Text without any is
// returned as is.
func stripHidden(s string) (string, []removal) {
	var removed []removal
	var kept []byte
	last := 0
	// prev is the last visible rune; base skips variation selectors back to
	// the emoji they modify.
	prev, base := rune(-1), rune(-1)
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if !IsHidden(r) {
			prev = r
			if r < 0xFE00 || r > 0xFE0F {
				base = r
			}
			i += size
			continue
		}
		// A run of invisible runes shares the visible runes around it.
		j := i
		for j < len(s) {
			rj, sj := utf8.DecodeRuneInString(s[j:])
			if !IsHidden(rj) {
				break
			}
			j += sj
		}
		next := rune(-1)
		if j < len(s) {
			next, _ = utf8.DecodeRuneInString(s[j:])
		}
		flagEnd := i
		if base == 0x1F3F4 {
			flagEnd += flagTags(s[i:j])
		}
		if kept == nil {
			kept = make([]byte, 0, len(s))
		}
		kept = append(kept, s[last:i]...)
		// One legitimate joiner, mark or BOM per run: a second one between
		// the same two neighbours does no job and counts.
		exempted := false
		for k := i; k < j; {
			rk, sk := utf8.DecodeRuneInString(s[k:])
			counted := false
			if k >= flagEnd && !hides(rk, k, prev, base, next) {
				counted, exempted = exempted, true
			} else if k >= flagEnd {
				counted = true
			}
			removed = append(removed, removal{at: k, size: sk, kept: len(kept), counted: counted})
			k += sk
		}
		last, i = j, j
	}
	if removed == nil {
		return s, nil
	}
	return string(append(kept, s[last:]...)), removed
}

// hides reports whether the invisible rune r at offset i hides something,
// given the visible runes around its run. The exceptions are the jobs these
// runes do in ordinary text: a byte order mark that opens a file, a joiner
// inside an emoji sequence or a non-Latin word, and direction marks and
// non-joiners in non-Latin text (Persian, Arabic, Hebrew). Fold allows one
// such exception per run of invisible runes.
func hides(r rune, i int, prev, base, next rune) bool {
	switch r {
	case 0xFEFF:
		return i != 0
	case 0x200C, 0x200E, 0x200F:
		return isLatinLetter(prev) && isLatinLetter(next)
	case 0x200D:
		if isPictographic(base) && isPictographic(next) {
			return false
		}
		return !isScriptLetter(prev) || !isScriptLetter(next)
	}
	return true
}

// flagTags returns the byte length of the tag sequence a subdivision flag
// (U+1F3F4 then tags) carries at the start of run: two to seven tag letters
// or digits ending in the cancel tag U+E007F, as in England's flag. Anything
// else, a tag-encoded sentence included, returns 0.
func flagTags(run string) int {
	n := 0
	for i := 0; i < len(run); {
		r, size := utf8.DecodeRuneInString(run[i:])
		i += size
		switch {
		case r == 0xE007F:
			if n >= 2 && n <= 7 {
				return i
			}
			return 0
		case r >= 0xE0030 && r <= 0xE0039, r >= 0xE0061 && r <= 0xE007A:
			n++
		default:
			return 0
		}
	}
	return 0
}

// isLatinLetter reports whether r is a Latin letter.
func isLatinLetter(r rune) bool {
	return unicode.Is(unicode.Latin, r)
}

// isScriptLetter reports whether r is a letter or mark of a script other
// than Latin, where joiners shape the text.
func isScriptLetter(r rune) bool {
	return r >= utf8.RuneSelf && (unicode.IsLetter(r) || unicode.IsMark(r)) && !unicode.Is(unicode.Latin, r)
}

// isPictographic approximates Unicode's Extended_Pictographic property, which
// the standard library does not carry.
func isPictographic(r rune) bool {
	switch {
	case r >= 0x1F000 && r <= 0x1FAFF, r >= 0x1FC00 && r <= 0x1FFFD,
		r >= 0x2600 && r <= 0x27BF, r >= 0x2300 && r <= 0x23FF,
		r >= 0x2B00 && r <= 0x2BFF, r >= 0x2190 && r <= 0x21FF,
		r >= 0x25A0 && r <= 0x25FF, r >= 0x2900 && r <= 0x297F,
		r == 0x00A9, r == 0x00AE, r == 0x203C, r == 0x2049, r == 0x2122,
		r == 0x2139, r == 0x24C2, r == 0x3030, r == 0x303D, r == 0x3297, r == 0x3299:
		return true
	}
	return false
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

// confusables maps Cyrillic and Greek letters to the Latin letters they look
// like. Fold applies it only inside words that also hold a Latin letter, so
// "ign\u043ere" (a Cyrillic o) folds to "ignore" while Russian or Greek text is
// left alone. The keys are lower case: Fold lowercases first.
var confusables = map[rune]byte{
	// Cyrillic
	'\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p', '\u0441': 'c',
	'\u0443': 'y', '\u0445': 'x', '\u0456': 'i', '\u0458': 'j', '\u0455': 's',
	'\u04bb': 'h', '\u0501': 'd', '\u051b': 'q', '\u051d': 'w', '\u04cf': 'l',
	'\u04af': 'y', '\u0475': 'v',
	// Greek
	'\u03bf': 'o', '\u03bd': 'v', '\u03b1': 'a', '\u03b9': 'i', '\u03ba': 'k',
	'\u03c1': 'p', '\u03c5': 'u', '\u03f2': 'c', '\u03f3': 'j',
}

// foldConfusables replaces confusable letters inside words that also hold a
// Latin letter, keeping the offset maps in step.
func foldConfusables(folded []byte, starts, ends []int32) (outFolded []byte, outStarts, outEnds []int32) {
	if !hasGreekOrCyrillic(folded) {
		return folded, starts, ends
	}
	outFolded = make([]byte, 0, len(folded))
	outStarts = make([]int32, 0, len(starts))
	outEnds = make([]int32, 0, len(ends))
	keep := func(from, to int) {
		outFolded = append(outFolded, folded[from:to]...)
		outStarts = append(outStarts, starts[from:to]...)
		outEnds = append(outEnds, ends[from:to]...)
	}
	for i := 0; i < len(folded); {
		r, size := utf8.DecodeRune(folded[i:])
		if !isWordRune(r) {
			keep(i, i+size)
			i += size
			continue
		}
		j, latin, lookalike := i, false, false
		for j < len(folded) {
			rj, sj := utf8.DecodeRune(folded[j:])
			if !isWordRune(rj) {
				break
			}
			latin = latin || isLatinLetter(rj)
			_, ok := confusables[rj]
			lookalike = lookalike || ok
			j += sj
		}
		if !latin || !lookalike {
			keep(i, j)
			i = j
			continue
		}
		for k := i; k < j; {
			rk, sk := utf8.DecodeRune(folded[k:])
			if c, ok := confusables[rk]; ok {
				outFolded = append(outFolded, c)
				outStarts = append(outStarts, starts[k])
				outEnds = append(outEnds, ends[k+sk-1])
			} else {
				keep(k, k+sk)
			}
			k += sk
		}
		i = j
	}
	return outFolded, outStarts, outEnds
}

// stripMarks drops the nonspacing marks of a segment whose base is a Latin
// letter or a lookalike, so "ig" + U+0307 + "nore" folds to "ignore". A
// precomposed letter such as the é in café has no separate mark and is left
// alone.
func stripMarks(seg string) string {
	base, size := utf8.DecodeRuneInString(seg)
	if !isLatinLetter(base) && !isLookalike(base) {
		return seg
	}
	if !strings.ContainsFunc(seg[size:], isNonspacingMark) {
		return seg
	}
	var b strings.Builder
	b.WriteString(seg[:size])
	for _, r := range seg[size:] {
		if !isNonspacingMark(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// isNonspacingMark reports whether r is a Unicode Mn combining mark.
func isNonspacingMark(r rune) bool {
	return unicode.Is(unicode.Mn, r)
}

// isLookalike reports whether r, in either case, is a confusable letter.
func isLookalike(r rune) bool {
	_, ok := confusables[unicode.ToLower(r)]
	return ok
}

// isWordRune reports whether r continues a word for the confusables check.
func isWordRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsMark(r)
}

// hasGreekOrCyrillic reports whether b may hold a Greek or Cyrillic letter:
// their UTF-8 lead bytes are 0xCD to 0xD4.
func hasGreekOrCyrillic(b []byte) bool {
	for _, c := range b {
		if c >= 0xCD && c <= 0xD4 {
			return true
		}
	}
	return false
}

// newlineIndex holds the offsets of every '\n' in a text, built once.
type newlineIndex struct {
	once sync.Once
	at   []int
}

// offsets returns the '\n' offsets of s, building them on the first call.
func (n *newlineIndex) offsets(s string) []int {
	n.once.Do(func() {
		for i := 0; ; {
			j := strings.IndexByte(s[i:], '\n')
			if j < 0 {
				break
			}
			n.at = append(n.at, i+j)
			i += j + 1
		}
	})
	return n.at
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
// A range that ends with a '\n' does not pull in the following line. It
// binary-searches a newline index, so many calls on one long line stay cheap.
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
	if t.newlines == nil {
		lineStart = strings.LastIndexByte(s[:start], '\n') + 1
		lineEnd = len(s)
		if i := strings.IndexByte(s[end:], '\n'); i >= 0 {
			lineEnd = end + i
		}
		return lineStart, lineEnd
	}
	at := t.newlines.offsets(s)
	if i, _ := slices.BinarySearch(at, start); i > 0 {
		lineStart = at[i-1] + 1
	}
	lineEnd = len(s)
	if j, _ := slices.BinarySearch(at, end); j < len(at) {
		lineEnd = at[j]
	}
	return lineStart, lineEnd
}

// Hidden returns the number of removed runes that hid something: every
// invisible rune Fold removed except a leading byte order mark, joiners in
// emoji sequences and non-Latin words, subdivision flag tags, and direction
// marks or non-joiners that do not sit between two Latin letters.
func (t Text) Hidden() int {
	return len(t.hidden)
}

// HiddenAt returns the original byte offset of every rune Hidden counts, in
// order.
func (t Text) HiddenAt() []int {
	return slices.Clone(t.hidden)
}

// offset narrows a byte offset for the per-byte maps, which halves their
// memory. Scans are capped far below 2 GiB, so it cannot overflow.
func offset(i int) int32 {
	return int32(i) //nolint:gosec // G115: scan input is capped far below 2 GiB
}
