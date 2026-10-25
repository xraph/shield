// Package detection holds the deterministic prompt-injection detectors that
// instincts run: a pattern corpus grouped into families, heuristics for
// hidden and encoded text, and canary tokens.
//
// Every detector takes a folded Text, matches its Folded form and reports
// matches as original byte offsets widened to whole lines, so a caller can
// redact or quote exactly the lines that carried the attack. A result's score
// is the noisy-or of its distinct families, each at its highest weight.
package detection

import (
	"regexp"
	"slices"
	"strings"

	"github.com/xraph/shield/instinct"
	"github.com/xraph/shield/internal/scoring"
	"github.com/xraph/shield/internal/textnorm"
)

// Text is folded text with a map back to the original. Build it with Fold.
type Text = textnorm.Text

// Fold builds the Text the detectors take: NFKC, lower case, zero-width and
// bidi controls removed, whitespace runs collapsed to one space.
func Fold(s string) Text {
	return textnorm.Fold(s)
}

// Family names a group of related detections.
type Family string

// Detection families.
const (
	// FamilyOverride is an instruction to ignore earlier instructions.
	FamilyOverride Family = "override"
	// FamilyRole is an attempt to reassign the model's role.
	FamilyRole Family = "role"
	// FamilyImpersonation is text posing as a system or assistant turn.
	FamilyImpersonation Family = "impersonation"
	// FamilyAgentDirective is text addressed to an AI agent, or telling one
	// to approve, merge, deploy or call a tool.
	FamilyAgentDirective Family = "agent_directive"
	// FamilyExfiltration asks for prompts, secrets or a data upload.
	FamilyExfiltration Family = "exfiltration"
	// FamilyJailbreak is a known jailbreak framing.
	FamilyJailbreak Family = "jailbreak"
	// FamilyManipulation claims approval or pushes past a safety step.
	FamilyManipulation Family = "manipulation"
	// FamilyHiddenText is a line carrying zero-width or bidi control runes.
	FamilyHiddenText Family = "hidden_text"
	// FamilyEncoded is a base64 run that decodes to a pattern match.
	FamilyEncoded Family = "encoded"
	// FamilyCanary is a canary token found in the text.
	FamilyCanary Family = "canary"
	// FamilyCustom is a match of a caller-supplied pattern.
	FamilyCustom Family = "custom"
)

// DefaultCustomWeight is the weight of a custom pattern when the caller gives
// none.
const DefaultCustomWeight = 0.8

// weights holds each built-in family's weight. Custom matches carry the
// caller's weight instead.
var weights = map[Family]float64{
	FamilyOverride:       0.9,
	FamilyImpersonation:  0.8,
	FamilyAgentDirective: 0.8,
	FamilyRole:           0.7,
	FamilyJailbreak:      0.7,
	FamilyExfiltration:   0.8,
	FamilyManipulation:   0.8,
	FamilyHiddenText:     0.6,
	FamilyEncoded:        0.8,
	FamilyCanary:         1,
}

// categories maps each instinct category to the pattern families it runs.
var categories = map[instinct.Category][]Family{
	instinct.CategoryInjection:    {FamilyOverride, FamilyImpersonation, FamilyAgentDirective, FamilyRole},
	instinct.CategoryManipulation: {FamilyAgentDirective, FamilyManipulation},
	instinct.CategoryJailbreak:    {FamilyRole, FamilyJailbreak},
	instinct.CategoryExfiltration: {FamilyExfiltration},
}

// Match is one detection. Start and End are original byte offsets covering
// the whole lines the match touched, without their trailing newlines.
type Match struct {
	Family Family  `json:"family"`
	Weight float64 `json:"weight"`
	Start  int     `json:"start"`
	End    int     `json:"end"`
}

// Result is the outcome of one detector. Score is in [0, 1]; zero means no
// match.
type Result struct {
	Score   float64 `json:"score"`
	Matches []Match `json:"matches,omitempty"`
}

// Families returns the pattern families a category runs, or nil for an
// unknown category.
func Families(cat instinct.Category) []Family {
	return slices.Clone(categories[cat])
}

// Patterns runs the corpus families of cat over t, plus every extra regex as
// family custom at extraWeight (DefaultCustomWeight when zero or negative,
// capped at 1). Extra regexes run on Folded, which is lower case.
func Patterns(t Text, cat instinct.Category, extra []*regexp.Regexp, extraWeight float64) Result {
	var c collector
	run := categories[cat]
	for _, p := range corpus {
		if slices.Contains(run, p.family) {
			p.each(t, func(start, end int) {
				c.add(t, p.family, weights[p.family], start, end)
			})
		}
	}
	if extraWeight <= 0 {
		extraWeight = DefaultCustomWeight
	}
	extraWeight = min(extraWeight, 1)
	for _, re := range extra {
		if re == nil {
			continue
		}
		for _, loc := range re.FindAllStringIndex(t.Folded, -1) {
			c.add(t, FamilyCustom, extraWeight, loc[0], loc[1])
		}
	}
	return c.result()
}

// Canary reports every line of t that holds token, compared in folded form,
// so case changes and hidden runes do not hide it. An empty token never
// matches.
func Canary(t Text, token string) Result {
	needle := strings.TrimSpace(textnorm.Fold(token).Folded)
	var c collector
	if needle == "" {
		return c.result()
	}
	for from := 0; from < len(t.Folded); {
		i := strings.Index(t.Folded[from:], needle)
		if i < 0 {
			break
		}
		start := from + i
		c.add(t, FamilyCanary, weights[FamilyCanary], start, start+len(needle))
		from = start + len(needle)
	}
	return c.result()
}

// collector gathers matches, dropping duplicates, and scores them.
type collector struct {
	matches []Match
	seen    map[Match]struct{}
}

// add records a match of family over the folded range [start, end).
func (c *collector) add(t Text, family Family, weight float64, start, end int) {
	os, oe := t.Span(start, end)
	c.addLines(family, weight, os, oe, t)
}

// addLines records a match of family over the original range [start, end),
// widened to whole lines.
func (c *collector) addLines(family Family, weight float64, start, end int, t Text) {
	ls, le := t.Lines(start, end)
	m := Match{Family: family, Weight: weight, Start: ls, End: le}
	if _, dup := c.seen[m]; dup {
		return
	}
	if c.seen == nil {
		c.seen = map[Match]struct{}{}
	}
	c.seen[m] = struct{}{}
	c.matches = append(c.matches, m)
}

// result sorts the matches and scores the distinct families.
func (c *collector) result() Result {
	if len(c.matches) == 0 {
		return Result{}
	}
	slices.SortFunc(c.matches, func(a, b Match) int {
		if a.Start != b.Start {
			return a.Start - b.Start
		}
		if a.End != b.End {
			return a.End - b.End
		}
		return strings.Compare(string(a.Family), string(b.Family))
	})
	return Result{Score: score(c.matches), Matches: c.matches}
}

// score is the noisy-or over distinct families, each at its highest weight.
func score(matches []Match) float64 {
	best := map[Family]float64{}
	for _, m := range matches {
		best[m.Family] = max(best[m.Family], m.Weight)
	}
	ws := make([]float64, 0, len(best))
	for _, w := range best {
		ws = append(ws, w)
	}
	return scoring.NoisyOr(ws...)
}
