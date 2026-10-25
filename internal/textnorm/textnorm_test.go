package textnorm_test

import (
	"strings"
	"testing"

	"github.com/xraph/shield/internal/textnorm"
)

func TestFoldRemovesHiddenAndFullwidth(t *testing.T) {
	got := textnorm.Fold("ig\u200bnore \uff30\uff32\uff25\uff36\uff29\uff2f\uff35\uff33")
	if got.Folded != "ignore previous" {
		t.Fatalf("Folded = %q, want %q", got.Folded, "ignore previous")
	}
	if got.Hidden() != 1 {
		t.Fatalf("Hidden() = %d, want 1", got.Hidden())
	}
}

func TestFoldRemovesBidiControlsAndCollapsesWhitespace(t *testing.T) {
	got := textnorm.Fold("\u202eA\u2066  B\u2069\n\n\tC\ufeff\u2060")
	if got.Folded != "a b c" {
		t.Fatalf("Folded = %q, want %q", got.Folded, "a b c")
	}
	if got.Hidden() != 5 {
		t.Fatalf("Hidden() = %d, want 5", got.Hidden())
	}
}

func TestSpanMapsBackToOriginal(t *testing.T) {
	original := "say: ig\u200bnore \uff30\uff32\uff25\uff36\uff29\uff2f\uff35\uff33 now"
	text := textnorm.Fold(original)
	start := strings.Index(text.Folded, "ignore previous")
	if start < 0 {
		t.Fatalf("Folded %q has no match", text.Folded)
	}
	os, oe := text.Span(start, start+len("ignore previous"))
	want := "ig\u200bnore \uff30\uff32\uff25\uff36\uff29\uff2f\uff35\uff33"
	if got := original[os:oe]; got != want {
		t.Fatalf("Original[%d:%d] = %q, want %q", os, oe, got, want)
	}
}

func TestSpanClampsOutOfRangeOffsets(t *testing.T) {
	text := textnorm.Fold("abc")
	if s, e := text.Span(-5, 99); s != 0 || e != 3 {
		t.Fatalf("Span(-5, 99) = (%d, %d), want (0, 3)", s, e)
	}
	if s, e := text.Span(3, 3); s != 3 || e != 3 {
		t.Fatalf("Span(3, 3) = (%d, %d), want (3, 3)", s, e)
	}
}

func TestLinesWidensToWholeLines(t *testing.T) {
	original := "a\nxx MATCH yy\nb"
	text := textnorm.Fold(original)
	start := strings.Index(original, "MATCH")
	ls, le := text.Lines(start, start+len("MATCH"))
	if got := original[ls:le]; got != "xx MATCH yy" {
		t.Fatalf("Lines = %q, want %q", got, "xx MATCH yy")
	}
	// A span that ends just after a newline stays on its own line.
	ls, le = text.Lines(2, 14)
	if got := original[ls:le]; got != "xx MATCH yy" {
		t.Fatalf("Lines(2, 14) = %q, want %q", got, "xx MATCH yy")
	}
}

func TestHiddenAtReportsOriginalOffsets(t *testing.T) {
	text := textnorm.Fold("ab\u200bc\n\u202ed")
	got := text.HiddenAt()
	if len(got) != 2 || got[0] != 2 || got[1] != 7 {
		t.Fatalf("HiddenAt() = %v, want [2 7]", got)
	}
}

func TestHiddenRuneInsideACompositionStaysMapped(t *testing.T) {
	original := "x e\u200b\u0301 y"
	text := textnorm.Fold(original)
	if text.Folded != "x \u00e9 y" {
		t.Fatalf("Folded = %q, want %q", text.Folded, "x \u00e9 y")
	}
	start := strings.Index(text.Folded, "\u00e9")
	os, oe := text.Span(start, start+len("\u00e9"))
	if got := original[os:oe]; got != "e\u200b\u0301" {
		t.Fatalf("Span covers %q", got)
	}
	os, oe = text.Span(start+len("\u00e9")+1, len(text.Folded))
	if got := original[os:oe]; got != "y" {
		t.Fatalf("Span after the composition covers %q", got)
	}
}

// FuzzFoldOffsets checks the offset map on arbitrary input, invalid UTF-8
// included: every folded byte maps into the original, starts never go
// backwards, and Lines covers the span inside the text.
func FuzzFoldOffsets(f *testing.F) {
	for _, seed := range []string{
		"",
		"ig\u200bnore \uff30\uff32\uff25\uff36\uff29\uff2f\uff35\uff33",
		"e\u200b\u0301\n\n\u202e x",
		"\xff\xfe a\u00a0b \ufb01",
		"line one\r\nline two\n",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		text := textnorm.Fold(s)
		prev := 0
		for i := range len(text.Folded) {
			os, oe := text.Span(i, i+1)
			if os < prev || os > oe || oe > len(s) {
				t.Fatalf("Span(%d, %d) = (%d, %d), previous start %d, original length %d", i, i+1, os, oe, prev, len(s))
			}
			prev = os
			// Lines drops a newline at either edge of the span, then covers
			// the rest.
			a, b := os, oe
			if b > a && s[b-1] == '\n' {
				b--
			}
			if b > a && s[a] == '\n' {
				a++
			}
			ls, le := text.Lines(os, oe)
			if ls < 0 || ls > a || le < b || le > len(s) {
				t.Fatalf("Lines(%d, %d) = (%d, %d)", os, oe, ls, le)
			}
		}
		if text.Hidden() != len(text.HiddenAt()) {
			t.Fatalf("Hidden() = %d, HiddenAt() has %d", text.Hidden(), len(text.HiddenAt()))
		}
	})
}
