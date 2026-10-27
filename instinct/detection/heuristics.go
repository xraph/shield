package detection

import (
	"encoding/base64"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// minBase64Run is the shortest base64 run checked for an encoded payload.
	minBase64Run = 40
	// minPrintable is the share of printable runes a decoded run needs before
	// its text is checked against the corpus.
	minPrintable = 0.9
)

// Heuristics runs the checks that are not phrase patterns:
//
//   - hidden_text: each line holding an invisible rune that Fold removed and
//     counts as hiding something (see Text.Hidden).
//   - encoded: each line holding a base64 run of 40 or more characters that
//     decodes to mostly printable text matching any corpus family.
func Heuristics(t Text) Result {
	var c collector
	// Offsets come in order, so one already inside the last matched line
	// adds nothing; skipping it keeps a long line of hidden runes linear.
	covered := -1
	for _, at := range t.HiddenAt() {
		if at < covered {
			continue
		}
		_, covered = t.Lines(at, at+1)
		c.addLines(FamilyHiddenText, weights[FamilyHiddenText], at, at+1, t)
	}
	for _, run := range base64Runs(t.Original) {
		decoded, ok := decodeBase64(t.Original[run[0]:run[1]])
		if ok && printable(decoded) && matchesAny(Fold(string(decoded))) {
			c.addLines(FamilyEncoded, weights[FamilyEncoded], run[0], run[1], t)
		}
	}
	return c.result()
}

// base64Runs returns the byte ranges of every run of at least minBase64Run
// base64 characters (standard or URL alphabet) in s, with up to two trailing
// '=' pads. It scans the original text, where case still matters.
func base64Runs(s string) [][2]int {
	var runs [][2]int
	for i := 0; i < len(s); {
		if !isBase64Byte(s[i]) {
			i++
			continue
		}
		start := i
		for i < len(s) && isBase64Byte(s[i]) {
			i++
		}
		if i-start < minBase64Run {
			continue
		}
		for pad := 0; pad < 2 && i < len(s) && s[i] == '='; pad++ {
			i++
		}
		runs = append(runs, [2]int{start, i})
	}
	return runs
}

// isBase64Byte reports whether b is in the standard or URL base64 alphabet.
func isBase64Byte(b byte) bool {
	return b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' ||
		b == '+' || b == '/' || b == '-' || b == '_'
}

// decodeBase64 decodes run with the standard or the URL alphabet, padded or
// not. A run that picked up up to three stray trailing characters from the
// text around it still decodes.
func decodeBase64(run string) ([]byte, bool) {
	raw := strings.TrimRight(run, "=")
	for trim := 0; trim < 4 && trim < len(raw); trim++ {
		candidate := raw[:len(raw)-trim]
		for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
			if b, err := enc.DecodeString(candidate); err == nil {
				return b, true
			}
		}
	}
	return nil, false
}

// printable reports whether at least minPrintable of b's runes are printable
// text. Invalid UTF-8 bytes count against it.
func printable(b []byte) bool {
	total, ok := 0, 0
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		b = b[size:]
		total++
		if r == utf8.RuneError && size == 1 {
			continue
		}
		if unicode.IsPrint(r) || r == '\n' || r == '\r' || r == '\t' {
			ok++
		}
	}
	return total > 0 && float64(ok) >= minPrintable*float64(total)
}
