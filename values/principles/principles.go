// Package principles holds the built-in detectors of the values layer: a
// curated lexicon for the safety principle (destructive infrastructure
// commands, the shell ones taken from instinct/detection) and the toxicity
// principle (abuse and threats aimed at people), and the score that turns
// pattern matches into a violation score.
//
// The patterns are written for folded text (see detection.Fold): lower
// case, one space between words. The engine scores the folded text.
//
// Lexicon entries are ASCII case-insensitive. Score counts their matches on
// a lower-cased copy of the text with a literal-prefix search, so a lexicon
// costs one fast pass per entry instead of a full regexp scan, and stays
// linear on large inputs. It counts exactly what the returned regexps find.
package principles

import (
	"bufio"
	"embed"
	"fmt"
	"math"
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/xraph/shield/instinct/detection"
	"github.com/xraph/shield/values"
)

// lexiconFiles holds one file per principle, named after it. Each line is
// "<category> <pattern>". Blank lines and lines starting with # are skipped.
//
// A pattern is written in lower case. It may start with \b, must then start
// with a literal, and may only use bounded repetition, so every match is
// short and starts with text Score can search for.
//
//go:embed lexicon/*.txt
var lexiconFiles embed.FS

// entry is one lexicon pattern.
type entry struct {
	principle values.Principle
	category  string
	// re is the public, ASCII case-insensitive pattern.
	re *regexp.Regexp
	// literal is the lower-case text every match starts with.
	literal string
	// wordStart says the pattern starts with \b.
	wordStart bool
	// anchored matches the pattern, \b stripped, at the start of
	// lower-cased text.
	anchored *regexp.Regexp
	// maxLen bounds the bytes of one match.
	maxLen int
}

var (
	lexicon []*entry
	// fast maps each lexicon regexp to its entry, for Score.
	fast = map[*regexp.Regexp]*entry{}
)

func init() {
	for _, p := range []values.Principle{values.PrincipleSafety, values.PrincipleToxicity} {
		name := "lexicon/" + string(p) + ".txt"
		data, err := lexiconFiles.ReadFile(name)
		if err != nil {
			panic(fmt.Sprintf("principles: %s: %v", name, err))
		}
		sc := bufio.NewScanner(strings.NewReader(string(data)))
		for line := 1; sc.Scan(); line++ {
			text := strings.TrimSpace(sc.Text())
			if text == "" || strings.HasPrefix(text, "#") {
				continue
			}
			category, source, ok := strings.Cut(text, " ")
			if !ok {
				panic(fmt.Sprintf("principles: %s:%d: want <category> <pattern>", name, line))
			}
			e, err := newEntry(p, category, strings.TrimSpace(source))
			if err != nil {
				panic(fmt.Sprintf("principles: %s:%d: %v", name, line, err))
			}
			lexicon = append(lexicon, e)
			fast[e.re] = e
		}
	}
	// The shell commands come from the injection detectors, so the safety
	// principle and the instincts never disagree on what destroys a tree.
	for _, source := range detection.DestructiveCommands() {
		if isWord(source[0]) {
			source = `\b` + source
		}
		e, err := newEntry(values.PrincipleSafety, categoryCommands, source)
		if err != nil {
			panic(fmt.Sprintf("principles: destructive command %q: %v", source, err))
		}
		lexicon = append(lexicon, e)
		fast[e.re] = e
	}
}

// categoryCommands is the safety category of the destructive shell commands
// taken from instinct/detection.
const categoryCommands = "commands"

// newEntry compiles one lexicon line.
func newEntry(p values.Principle, category, source string) (*entry, error) {
	e := &entry{principle: p, category: category}
	body := source
	if rest, ok := strings.CutPrefix(source, `\b`); ok {
		e.wordStart, body = true, rest
	}
	tree, err := syntax.Parse(body, syntax.Perl)
	if err != nil {
		return nil, err
	}
	e.literal, err = leadingLiteral(tree)
	if err != nil {
		return nil, err
	}
	if e.wordStart && !isWord(e.literal[0]) {
		return nil, fmt.Errorf("\\b before the non-word literal %q", e.literal)
	}
	if e.maxLen, err = maxLength(tree); err != nil {
		return nil, err
	}
	if lowerErr := lowerOnly(tree); lowerErr != nil {
		return nil, lowerErr
	}
	if e.anchored, err = regexp.Compile(`^(?:` + body + `)`); err != nil {
		return nil, err
	}
	public := caseless(tree).String()
	if e.wordStart {
		public = `\b` + public
	}
	if e.re, err = regexp.Compile(public); err != nil {
		return nil, err
	}
	return e, nil
}

// leadingLiteral returns the literal a pattern starts with.
func leadingLiteral(re *syntax.Regexp) (string, error) {
	first := re
	if re.Op == syntax.OpConcat && len(re.Sub) > 0 {
		first = re.Sub[0]
	}
	if first.Op != syntax.OpLiteral || first.Flags&syntax.FoldCase != 0 {
		return "", fmt.Errorf("pattern must start with a literal")
	}
	lit := string(first.Rune)
	for i := range len(lit) {
		if lit[i] >= utf8.RuneSelf {
			return "", fmt.Errorf("literal %q is not ASCII", lit)
		}
	}
	return lit, nil
}

// maxLength bounds the bytes one match of re can span.
func maxLength(re *syntax.Regexp) (int, error) {
	switch re.Op {
	case syntax.OpLiteral:
		n := 0
		for _, r := range re.Rune {
			n += utf8.RuneLen(r)
		}
		return n, nil
	case syntax.OpCharClass, syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return utf8.UTFMax, nil
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine, syntax.OpEndText,
		syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return 0, nil
	case syntax.OpCapture, syntax.OpQuest:
		return maxLength(re.Sub[0])
	case syntax.OpRepeat:
		if re.Max < 0 {
			return 0, fmt.Errorf("unbounded repetition")
		}
		n, err := maxLength(re.Sub[0])
		return n * re.Max, err
	case syntax.OpConcat, syntax.OpAlternate:
		total := 0
		for _, sub := range re.Sub {
			n, err := maxLength(sub)
			if err != nil {
				return 0, err
			}
			if re.Op == syntax.OpConcat {
				total += n
			} else {
				total = max(total, n)
			}
		}
		return total, nil
	default:
		// Star, plus, begin text and no-match are not allowed: the first
		// two are unbounded and a pattern never anchors to the text start.
		return 0, fmt.Errorf("unsupported operator %s", re.Op)
	}
}

// lowerOnly rejects upper-case letters in literals: Score matches lower-cased
// text, where they never occur.
func lowerOnly(re *syntax.Regexp) error {
	if re.Op == syntax.OpLiteral {
		for _, r := range re.Rune {
			if r >= 'A' && r <= 'Z' {
				return fmt.Errorf("upper-case letter in literal %q", string(re.Rune))
			}
		}
	}
	for _, sub := range re.Sub {
		if err := lowerOnly(sub); err != nil {
			return err
		}
	}
	return nil
}

// caseless returns a copy of re that matches a character c exactly when re
// matches c lower-cased (ASCII only), so it agrees with re run on
// lower-cased text.
func caseless(re *syntax.Regexp) *syntax.Regexp {
	out := *re
	out.Sub = make([]*syntax.Regexp, len(re.Sub))
	for i, sub := range re.Sub {
		out.Sub[i] = caseless(sub)
	}
	switch re.Op {
	case syntax.OpLiteral:
		subs := make([]*syntax.Regexp, 0, len(re.Rune))
		for _, r := range re.Rune {
			subs = append(subs, charClass(lowerClass([]rune{r, r})))
		}
		if len(subs) == 1 {
			return subs[0]
		}
		return &syntax.Regexp{Op: syntax.OpConcat, Sub: subs}
	case syntax.OpCharClass:
		out.Rune = lowerClass(re.Rune)
		if len(out.Rune) == 0 {
			return &syntax.Regexp{Op: syntax.OpNoMatch}
		}
	}
	return &out
}

func charClass(ranges []rune) *syntax.Regexp {
	return &syntax.Regexp{Op: syntax.OpCharClass, Rune: ranges}
}

// lowerClass returns the ranges of characters whose ASCII lower case is in
// ranges: upper-case letters are dropped, and each lower-case letter brings
// its upper case.
func lowerClass(ranges []rune) []rune {
	var out []rune
	add := func(lo, hi rune) {
		if lo <= hi {
			out = append(out, lo, hi)
		}
	}
	for i := 0; i+1 < len(ranges); i += 2 {
		lo, hi := ranges[i], ranges[i+1]
		// The part below 'A', between 'Z' and 'a', and above 'z' as is,
		// upper-case letters dropped.
		add(lo, min(hi, 'A'-1))
		add(max(lo, 'Z'+1), hi)
		// Each lower-case letter adds its upper case.
		if l, h := max(lo, 'a'), min(hi, 'z'); l <= h {
			add(l-'a'+'A', h-'a'+'A')
		}
	}
	return normalize(out)
}

// normalize sorts and merges ranges.
func normalize(ranges []rune) []rune {
	type span struct{ lo, hi rune }
	spans := make([]span, 0, len(ranges)/2)
	for i := 0; i+1 < len(ranges); i += 2 {
		spans = append(spans, span{ranges[i], ranges[i+1]})
	}
	slices.SortFunc(spans, func(a, b span) int { return int(a.lo - b.lo) })
	var out []rune
	for _, s := range spans {
		if n := len(out); n > 0 && s.lo <= out[n-1]+1 {
			out[n-1] = max(out[n-1], s.hi)
			continue
		}
		out = append(out, s.lo, s.hi)
	}
	return out
}

// Lexicon returns the built-in patterns of principle p in the given
// categories, or in every category when categories is empty. It returns nil
// for a principle without a built-in lexicon: only safety and toxicity have
// one. The patterns are ASCII case-insensitive.
func Lexicon(p values.Principle, categories []string) []*regexp.Regexp {
	var out []*regexp.Regexp
	known := false
	for _, e := range lexicon {
		if e.principle != p {
			continue
		}
		known = true
		if len(categories) == 0 || slices.Contains(categories, e.category) {
			out = append(out, e.re)
		}
	}
	if known && out == nil {
		out = []*regexp.Regexp{}
	}
	return out
}

// Score counts the matches of patterns in text and combines them as a
// noisy-or with 0.5 per match: one match scores 0.5, two 0.75, three 0.875.
// It returns the score and the match count. Matches of one pattern do not
// overlap; matches of different patterns may.
func Score(text string, patterns []*regexp.Regexp) (score float64, count int) {
	count = NewScorer(patterns).Count(text)
	return 1 - math.Pow(0.5, float64(count)), count
}

// Scorer counts the matches of a fixed set of patterns, as Score does. It
// groups the built-in lexicon once, so counting many short texts against
// the same patterns stays cheap.
type Scorer struct {
	slow   []*regexp.Regexp
	groups []literalGroup
}

// literalGroup is the lexicon entries that share one literal.
type literalGroup struct {
	literal string
	entries []*entry
}

// NewScorer prepares patterns for Count. Nil patterns are skipped.
func NewScorer(patterns []*regexp.Regexp) *Scorer {
	s := &Scorer{}
	index := map[string]int{}
	for _, re := range patterns {
		if re == nil {
			continue
		}
		e, ok := fast[re]
		if !ok {
			s.slow = append(s.slow, re)
			continue
		}
		k, seen := index[e.literal]
		if !seen {
			k = len(s.groups)
			index[e.literal] = k
			s.groups = append(s.groups, literalGroup{literal: e.literal})
		}
		s.groups[k].entries = append(s.groups[k].entries, e)
	}
	return s
}

// Count returns the number of matches of the scorer's patterns in text.
func (s *Scorer) Count(text string) int {
	count := 0
	for _, re := range s.slow {
		count += len(re.FindAllStringIndex(text, -1))
	}
	if len(s.groups) > 0 {
		lower := asciiLower(text)
		for _, g := range s.groups {
			count += countLiteralGroup(lower, g.literal, g.entries)
		}
	}
	return count
}

// countLiteralGroup counts the matches of entries that share literal in the
// lower-cased text. It visits each place the literal occurs once and tries
// every entry there, keeping each entry's matches apart from each other the
// way FindAll does.
func countLiteralGroup(lower, literal string, entries []*entry) int {
	n := 0
	next := make([]int, len(entries)) // where each entry's next match may start
	for off := 0; off < len(lower); {
		i := strings.Index(lower[off:], literal)
		if i < 0 {
			break
		}
		pos := off + i
		off = pos + 1
		wordStart := pos == 0 || !isWord(lower[pos-1])
		for k, e := range entries {
			if pos < next[k] || e.wordStart && !wordStart {
				continue
			}
			// One byte past the longest match lets a trailing \b or $ see
			// what follows.
			end := min(len(lower), pos+e.maxLen+1)
			if loc := e.anchored.FindStringIndex(lower[pos:end]); loc != nil {
				n++
				next[k] = pos + max(loc[1], 1)
			}
		}
	}
	return n
}

// asciiLower lower-cases ASCII letters and keeps every other byte, so byte
// offsets do not move.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// isWord reports whether c is an ASCII word byte, as \b sees it.
func isWord(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}
