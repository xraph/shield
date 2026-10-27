package scan

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/xraph/shield/internal/textnorm"
)

// QuoteTag is the element Quote wraps untrusted text in.
const QuoteTag = "untrusted_content"

// closingTag is the start of the tag that would end the wrapper early.
const closingTag = "</" + QuoteTag

// Quote wraps untrusted text so a model reads it as data, not as
// instructions:
//
//	<untrusted_content source="S">
//	text
//	</untrusted_content>
//
// Every tag inside text that a model could read as the wrapper's own, opening
// or closing, gets a backslash right after its "<" ("<\/untrusted_content",
// "<\untrusted_content"), so the only closing tag is the last line. The match
// runs on the folded text (see textnorm.Fold) and so sees through letter
// case, fullwidth and other compatibility forms, Cyrillic, Greek and other
// lookalike letters, a "-", a space or no separator in place of the "_",
// whitespace after the "<" or the "/", and invisible runes and combining
// marks anywhere inside the tag. Every byte of text is kept; only the
// backslashes are added. HTML entities and URL encoding
// ("&lt;/untrusted_content&gt;", "%3C/untrusted_content") are the escaped
// form of a literal tag, which a model reads as data, and are left alone. S is source in lower case with every rune other
// than a to z, 0 to 9, '_', '.' and '-' replaced by '_'; an empty source is
// "unknown".
func Quote(source, text string) string {
	var b strings.Builder
	b.Grow(len(text) + len(source) + 2*len(QuoteTag) + 24)
	b.WriteString("<" + QuoteTag + ` source="`)
	b.WriteString(quoteSource(source))
	b.WriteString("\">\n")
	writeEscaped(&b, text)
	b.WriteString("\n" + closingTag + ">")
	return b.String()
}

// quoteSource sanitizes a source name for the wrapper's attribute.
func quoteSource(source string) string {
	if source == "" {
		return "unknown"
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_', r == '.', r == '-':
			return r
		}
		return '_'
	}, strings.ToLower(source))
}

// lessThans are the runes that can open a tag after folding: "<" and its
// lookalikes. The fullwidth and small forms fold to "<".
const lessThans = "<\u02c2\u2039\u1438\u3008\u27e8\uff1c\ufe64\u2329"

// writeEscaped writes text with a backslash after the "<" of every tag a
// model could read as the wrapper's. Text without any "<" is written as is.
func writeEscaped(b *strings.Builder, text string) {
	if !strings.ContainsAny(text, lessThans) {
		b.WriteString(text)
		return
	}
	t := textnorm.Fold(text)
	folded := t.Folded
	last := 0
	for i := 0; i < len(folded); {
		r, size := utf8.DecodeRuneInString(folded[i:])
		if isLessThan(r) && tagAfter(t, i+size) {
			// Right after the original "<", before any invisible rune that
			// followed it.
			if _, end := t.Span(i, i+size); end >= last {
				b.WriteString(text[last:end])
				b.WriteByte('\\')
				last = end
			}
		}
		i += size
	}
	b.WriteString(text[last:])
}

// tagAfter reports whether folded text at i continues a "<" into the
// wrapper's tag: optional whitespace, an optional "/", optional whitespace,
// "untrusted", any run of separator runes and "content", with ignorable runes
// anywhere. It never reads past the next "<", so the scans from all the "<"
// in a text stay linear together.
func tagAfter(t textnorm.Text, i int) bool {
	folded := t.Folded
	i = skip(folded, i, true)
	if r, size := utf8.DecodeRuneInString(folded[i:]); isSlash(r) {
		i = skip(folded, i+size, true)
	}
	var ok bool
	if i, ok = word(t, i, "untrusted"); !ok {
		return false
	}
	for {
		i = skip(folded, i, false)
		r, size := utf8.DecodeRuneInString(folded[i:])
		if !isSeparator(r) {
			break
		}
		i += size
	}
	_, ok = word(t, i, "content")
	return ok
}

// word matches the letters of w at folded offset i, through lookalikes, with
// ignorable runes between them, and returns the offset after the last one.
func word(t textnorm.Text, i int, w string) (int, bool) {
	folded := t.Folded
	for k := range len(w) {
		i = skip(folded, i, false)
		r, size := utf8.DecodeRuneInString(folded[i:])
		if size == 0 || letterAt(t, i, size, r) != rune(w[k]) {
			return i, false
		}
		i += size
	}
	return i, true
}

// letterAt returns the ASCII letter the folded rune r at [i, i+size) reads
// as. A Greek letter is read from the original text, before Fold lowers and
// folds it: capital Nu lowers to nu, which Fold turns into "v" inside a
// Latin word, yet it reads as "N".
func letterAt(t textnorm.Text, i, size int, r rune) rune {
	if start, _ := t.Span(i, i+size); start < len(t.Original) {
		orig, _ := utf8.DecodeRuneInString(t.Original[start:])
		if c, ok := greekLookalikes[orig]; ok {
			return c
		}
	}
	return latinOf(r)
}

// skip passes the ignorable runes at i, and whitespace too when spaces is
// set.
func skip(folded string, i int, spaces bool) int {
	for i < len(folded) {
		r, size := utf8.DecodeRuneInString(folded[i:])
		if !isIgnorable(r) && (!spaces || r != ' ') {
			break
		}
		i += size
	}
	return i
}

// isIgnorable reports whether a model may read past r without seeing it:
// combining marks of every kind (variation selectors among them), format
// characters, and the Hangul fillers. Fold has already removed the
// zero-width and bidi runes.
func isIgnorable(r rune) bool {
	switch r {
	case 0x115F, 0x1160, 0x3164, 0xFFA0:
		return true
	}
	return r >= utf8.RuneSelf && (unicode.In(r, unicode.Mn, unicode.Me, unicode.Mc, unicode.Cf))
}

func isLessThan(r rune) bool {
	return r == '<' || r >= utf8.RuneSelf && strings.ContainsRune(lessThans, r)
}

// isSlash reports whether r reads as "/". The fullwidth form folds to it.
func isSlash(r rune) bool {
	switch r {
	case '/', 0x2044, 0x2215, 0x29F8, 0x2571, 0x27CB:
		return true
	}
	return false
}

// isSeparator reports whether r can stand between the tag's two words: a
// space, "_", or "-" and its lookalikes (hyphens, dashes, minus signs).
func isSeparator(r rune) bool {
	switch r {
	case ' ', '_', '-', 0x2010, 0x2011, 0x2012, 0x2013, 0x2014, 0x2015, 0x2212, 0xFE58, 0x2E3A, 0x2E3B:
		return true
	}
	return false
}

// tagLookalikes maps letters that look like the tag's Latin letters to them,
// for runes Fold leaves alone: Cyrillic, Greek and Armenian letters outside
// a Latin word, and small capitals. Fold has already lowered the case and
// mapped the fullwidth, mathematical and circled forms.
var tagLookalikes = map[rune]rune{
	// Cyrillic
	0x0441: 'c', 0x043E: 'o', 0x0435: 'e', 0x0455: 's', 0x0501: 'd', 0x0442: 't',
	0x0433: 'r', 0x043F: 'n', 0x04BD: 'e',
	// Greek, as Fold leaves it (see also greekLookalikes)
	0x03BF: 'o', 0x03C5: 'u', 0x03C4: 't', 0x03B7: 'n', 0x03F2: 'c',
	0x03C2: 'c', // NFKC turns the lunate sigma U+03F2 into the final sigma
	// Armenian
	0x0585: 'o', 0x057D: 'u', 0x0578: 'n', 0x057C: 'n',
	// Small capitals and other Latin forms
	0x1D1C: 'u', 0x0274: 'n', 0x1D1B: 't', 0x0280: 'r', 0xA731: 's', 0x1D07: 'e',
	0x1D05: 'd', 0x1D04: 'c', 0x1D0F: 'o', 0x028B: 'u',
}

// greekLookalikes maps Greek letters, capital and small, to the Latin
// letters they look like. letterAt reads them from the original text.
var greekLookalikes = map[rune]rune{
	0x0391: 'a', 0x0392: 'b', 0x0395: 'e', 0x0396: 'z', 0x0397: 'h', 0x0399: 'i', 0x039A: 'k',
	0x039C: 'm', 0x039D: 'n', 0x039F: 'o', 0x03A1: 'p', 0x03A4: 't', 0x03A5: 'y', 0x03A7: 'x',
	0x03B1: 'a', 0x03B2: 'b', 0x03B5: 'e', 0x03B6: 'z', 0x03B7: 'n', 0x03B9: 'i', 0x03BA: 'k',
	0x03BC: 'u', 0x03BD: 'n', 0x03BF: 'o', 0x03C1: 'p', 0x03C4: 't', 0x03C5: 'u', 0x03C7: 'x',
	0x03F2: 'c',
}

// latinOf returns the ASCII letter r reads as, or 0. A letter that composed
// with a mark after folding ("o" and U+0301 to "\u00f3") reads as its base.
func latinOf(r rune) rune {
	if r < utf8.RuneSelf {
		return r
	}
	if c, ok := tagLookalikes[r]; ok {
		return c
	}
	var buf [utf8.UTFMax]byte
	if d := norm.NFD.Properties(utf8.AppendRune(buf[:0], r)).Decomposition(); d != nil {
		base, _ := utf8.DecodeRune(d)
		if base < utf8.RuneSelf {
			return base
		}
		return tagLookalikes[base]
	}
	return 0
}
