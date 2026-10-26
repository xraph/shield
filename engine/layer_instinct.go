package engine

import (
	"context"
	"slices"

	"github.com/xraph/shield/awareness/perception"
	"github.com/xraph/shield/instinct"
	"github.com/xraph/shield/instinct/detection"
	"github.com/xraph/shield/internal/scoring"
	"github.com/xraph/shield/scan"
)

// instinctMessages are the fixed finding messages, by category.
var instinctMessages = map[instinct.Category]string{
	instinct.CategoryInjection:    "suspected prompt injection",
	instinct.CategoryExfiltration: "suspected data exfiltration attempt",
	instinct.CategoryManipulation: "suspected manipulation",
	instinct.CategoryJailbreak:    "suspected jailbreak attempt",
}

// runInstincts is layer 1. Each instinct scores the text with its
// strategies, combined as 1 - Π(1 - weight·score), and fires when the score
// reaches the threshold of its sensitivity.
func (e *Engine) runInstincts(ctx context.Context, ev *evaluation) {
	for _, inst := range ev.profile.instincts {
		score, matches := ev.scoreInstinct(inst)
		if len(matches) == 0 || score < inst.threshold {
			continue
		}
		spans := lineSpans(matches)
		message, ok := instinctMessages[inst.category]
		if !ok {
			message = "suspected unsafe instruction"
		}
		ev.add(&scan.Finding{
			Layer: layerInstinct, Source: inst.name, Message: message, Score: score, Action: inst.action,
			Details: map[string]any{"families": families(matches), "count": len(spans), "spans": spans},
		})
		switch inst.action {
		case instinct.ActionRedact:
			for _, s := range spans {
				ev.removals = append(ev.removals, perception.Span{Start: s[0], End: s[1], Placeholder: removedInstruction})
			}
		case instinct.ActionQuote:
			ev.quote = true
		}
		e.registry.EmitInstinctTriggered(ctx, ev.scanID, inst.name, score)
	}
}

// scoreInstinct runs the instinct's strategies and returns the combined
// score and every match. An unsupported strategy scores 0 and is reported
// as an info finding.
func (ev *evaluation) scoreInstinct(inst *compiledInstinct) (float64, []detection.Match) {
	weighted := make([]float64, 0, len(inst.strategies))
	var matches []detection.Match
	for _, s := range inst.strategies {
		var res detection.Result
		switch s.name {
		case strategyPatterns:
			res = detection.Patterns(ev.foldedText(), inst.category, s.patterns, s.patternWeight)
		case strategyHeuristics:
			res = detection.Heuristics(ev.foldedText())
		case strategyCanary:
			res = detection.Canary(ev.foldedText(), s.token)
		default:
			ev.info(layerInstinct, inst.name, "unsupported strategy "+s.name)
			continue
		}
		weighted = append(weighted, s.weight*res.Score)
		matches = append(matches, res.Matches...)
	}
	return scoring.NoisyOr(weighted...), matches
}

// lineSpans merges the matched line ranges, in order.
func lineSpans(matches []detection.Match) [][2]int {
	order := slices.Clone(matches)
	slices.SortFunc(order, func(a, b detection.Match) int { return a.Start - b.Start })
	var out [][2]int
	for _, m := range order {
		if n := len(out); n > 0 && m.Start <= out[n-1][1] {
			out[n-1][1] = max(out[n-1][1], m.End)
			continue
		}
		out = append(out, [2]int{m.Start, m.End})
	}
	return out
}

// families returns the distinct families of matches, sorted.
func families(matches []detection.Match) []string {
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		if f := string(m.Family); !slices.Contains(out, f) {
			out = append(out, f)
		}
	}
	slices.Sort(out)
	return out
}
