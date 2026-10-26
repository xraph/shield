package engine

import (
	"context"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/xraph/shield/boundary"
	"github.com/xraph/shield/instinct/detection"
	"github.com/xraph/shield/scan"
)

// compiledBoundary is a boundary with its deny entries folded the way the
// scanned text is.
type compiledBoundary struct {
	name     string
	response string
	limits   []compiledLimit
}

// compiledLimit is one limit of a boundary.
type compiledLimit struct {
	scope    boundary.Scope
	deny     []string // folded, empty entries dropped
	allow    []string
	useAllow bool
}

func compileBoundary(b *boundary.Boundary) *compiledBoundary {
	cb := &compiledBoundary{name: b.Name, response: b.Response}
	for _, l := range b.Limits {
		cl := compiledLimit{scope: l.Scope, allow: l.Allow, useAllow: l.UseAllow}
		for _, d := range l.Deny {
			if folded := strings.TrimSpace(detection.Fold(d).Folded); folded != "" {
				cl.deny = append(cl.deny, folded)
			}
		}
		cb.limits = append(cb.limits, cl)
	}
	return cb
}

// runBoundaries is layer 3: hard limits. Deny entries match the folded text
// (case, width, spacing and invisible runes do not matter): topic entries as
// whole words or phrases, data and output entries anywhere. A topic
// allowlist blocks any awareness topic label it does not list; no label, no
// block. Output limits apply to output scans only, and action limits to
// tool calls only. A crossed boundary blocks with its canned response.
func (e *Engine) runBoundaries(ctx context.Context, ev *evaluation) {
	for _, b := range ev.profile.boundaries {
		scope, crossed := ev.crossed(b)
		if !crossed {
			continue
		}
		ev.add(&scan.Finding{
			Layer: layerBoundary, Source: b.name, Message: "content crosses a " + string(scope) + " boundary",
			Score: 1, Action: actionBlock,
			Details: map[string]any{"scope": string(scope), "response": b.response},
		})
		e.registry.EmitBoundaryEnforced(ctx, ev.scanID, b.name)
	}
}

// crossed reports the first limit of b the text crosses. Every limit the
// engine cannot enforce on this scan gives an info finding, also after a
// crossed one.
func (ev *evaluation) crossed(b *compiledBoundary) (boundary.Scope, bool) {
	folded := ev.foldedText().Folded
	var hit boundary.Scope
	cross := func(scope boundary.Scope) {
		if hit == "" {
			hit = scope
		}
	}
	for _, l := range b.limits {
		switch l.scope {
		case boundary.ScopeTopic:
			if hit != "" {
				continue
			}
			for _, d := range l.deny {
				if countWords(folded, d, 1) > 0 {
					cross(l.scope)
				}
			}
			if l.useAllow {
				for _, label := range ev.labels {
					if !slices.Contains(l.allow, label) {
						cross(l.scope)
					}
				}
			}
		case boundary.ScopeData, boundary.ScopeOutput:
			if l.scope == boundary.ScopeOutput && ev.input.Direction != scan.DirectionOutput {
				continue
			}
			if l.useAllow {
				ev.info(layerBoundary, b.name, "allowlist unsupported for scope "+string(l.scope))
			}
			if hit != "" {
				continue
			}
			for _, d := range l.deny {
				if strings.Contains(folded, d) {
					cross(l.scope)
				}
			}
		case boundary.ScopeAction:
			ev.info(layerBoundary, b.name, "action limits apply to tool calls only")
		default:
			ev.info(layerBoundary, b.name, "unsupported boundary scope "+string(l.scope))
		}
	}
	return hit, hit != ""
}

// countWords counts the occurrences of phrase in text as a whole word or
// phrase, up to limit (0 means all): an edge of phrase that is a letter,
// digit or underscore must not continue into one in text. Occurrences do
// not overlap.
func countWords(text, phrase string, limit int) int {
	if phrase == "" {
		return 0
	}
	first, _ := utf8.DecodeRuneInString(phrase)
	last, _ := utf8.DecodeLastRuneInString(phrase)
	n := 0
	for off := 0; off < len(text); {
		i := strings.Index(text[off:], phrase)
		if i < 0 {
			break
		}
		start, end := off+i, off+i+len(phrase)
		before, _ := utf8.DecodeLastRuneInString(text[:start])
		after, _ := utf8.DecodeRuneInString(text[end:])
		if (start == 0 || !isWordRune(first) || !isWordRune(before)) &&
			(end == len(text) || !isWordRune(last) || !isWordRune(after)) {
			n++
			if n == limit {
				break
			}
			off = end
			continue
		}
		_, size := utf8.DecodeRuneInString(text[start:])
		off = start + size
	}
	return n
}

func isWordRune(r rune) bool {
	return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r)
}
