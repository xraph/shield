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

// runInstincts is layer 1. Each instinct scores each unit of the text with
// its strategies, combined as 1 - Π(1 - weight·score), and fires when a
// unit's score reaches the threshold of its sensitivity. The finding takes
// the highest unit score and the lines of every unit that reached it.
func (e *Engine) runInstincts(ctx context.Context, ev *evaluation) {
	for _, inst := range ev.profile.instincts {
		if detection.Families(inst.category) == nil {
			// A category written straight to the store that shield has no
			// corpus for: only its custom patterns, heuristics and canary
			// run.
			ev.add(&scan.Finding{
				Layer: layerInstinct, Source: inst.name, Message: "no corpus for the instinct's category", Action: actionInfo,
				Details: map[string]any{"category": string(inst.category)},
			})
		}
		for _, s := range inst.strategies {
			if !slices.Contains([]string{strategyPatterns, strategyHeuristics, strategyCanary}, s.name) {
				ev.info(layerInstinct, inst.name, "unsupported strategy "+s.name)
			}
		}
		best := 0.0
		var matches []detection.Match
		var units []int
		for _, group := range ev.distinct {
			score, found := scoreInstinct(inst, ev.unitFolded(group[0]))
			if len(found) == 0 || score < inst.threshold {
				continue
			}
			best = max(best, score)
			for _, u := range group {
				units = append(units, u)
				for _, m := range found {
					m.Start += ev.units[u].start
					m.End += ev.units[u].start
					matches = append(matches, m)
				}
			}
		}
		if len(units) == 0 {
			continue
		}
		slices.Sort(units)
		spans := lineSpans(matches)
		message, ok := instinctMessages[inst.category]
		if !ok {
			message = "suspected unsafe instruction"
		}
		f := &scan.Finding{
			Layer: layerInstinct, Source: inst.name, Message: message, Score: best, Action: inst.action,
			Details: map[string]any{"families": families(matches), "count": len(spans), "spans": spans},
		}
		ev.add(f)
		ev.noteUnits(f, units)
		switch inst.action {
		case instinct.ActionRedact:
			for _, s := range spans {
				ev.removals = append(ev.removals, perception.Span{Start: s[0], End: s[1], Placeholder: removedInstruction})
			}
		case instinct.ActionQuote:
			ev.quote = true
		}
		e.registry.EmitInstinctTriggered(ctx, ev.scanID, inst.name, best)
	}
}

// scoreInstinct runs the instinct's strategies over t and returns the
// combined score and every match. An unsupported strategy scores 0.
func scoreInstinct(inst *compiledInstinct, t detection.Text) (float64, []detection.Match) {
	weighted := make([]float64, 0, len(inst.strategies))
	var matches []detection.Match
	for _, s := range inst.strategies {
		var res detection.Result
		switch s.name {
		case strategyPatterns:
			res = detection.Patterns(t, inst.category, s.patterns, s.patternWeight)
		case strategyHeuristics:
			res = detection.Heuristics(t)
		case strategyCanary:
			res = detection.Canary(t, s.token)
		default:
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
