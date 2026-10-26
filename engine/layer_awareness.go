package engine

import (
	"context"

	"github.com/xraph/shield/awareness"
	"github.com/xraph/shield/awareness/perception"
	"github.com/xraph/shield/scan"
)

// awarenessMessages are the fixed finding messages, by focus.
var awarenessMessages = map[awareness.Focus]string{
	awareness.FocusPII:     "personal data detected",
	awareness.FocusSecrets: "secret detected",
}

// detected is what one awareness detector found.
type detected struct {
	detector string
	focus    awareness.Focus
	matches  []perception.Match
}

// runAwareness is layer 2. Personal data and secret detectors run the
// built-ins they name plus their own patterns, custom detectors run their
// patterns, and topic detectors record a label when a pattern matches. Each
// detector that finds something gives one finding; a detector the engine
// cannot run gives an info finding.
func (e *Engine) runAwareness(ctx context.Context, ev *evaluation) {
	for _, a := range ev.profile.awareness {
		var found []detected
		for _, d := range a.detectors {
			found = append(found, ev.runDetector(a, d)...)
		}
		total := 0
		for _, f := range found {
			if len(f.matches) == 0 {
				continue
			}
			ev.recordAwareness(ctx, e, a, f)
			total += countSpans(f.matches)
		}
		if total > 0 {
			e.registry.EmitAwarenessDetected(ctx, ev.scanID, a.name, total)
		}
	}
}

// runDetector runs one detector and returns its matches grouped by
// detector name.
func (ev *evaluation) runDetector(a *compiledAwareness, d compiledDetector) []detected {
	text := ev.input.Text
	switch d.focus {
	case awareness.FocusPII, awareness.FocusSecrets:
		if !d.builtin && len(d.patterns) == 0 {
			ev.info(layerAwareness, a.name, "unsupported detector "+d.name)
			return nil
		}
		var matches []perception.Match
		if d.builtin {
			var names []string
			if !d.all {
				names = []string{d.name}
			}
			if d.focus == awareness.FocusPII {
				matches = perception.PII(text, names)
			} else {
				matches = perception.Secrets(text, names)
			}
		}
		if len(d.patterns) > 0 {
			matches = append(matches, perception.Custom(text, d.name, d.patterns)...)
		}
		if !d.all {
			return []detected{{detector: d.name, focus: d.focus, matches: matches}}
		}
		return byDetector(d.focus, matches)
	case awareness.FocusTopic:
		if len(d.patterns) == 0 {
			ev.info(layerAwareness, a.name, "unsupported detector "+d.name)
			return nil
		}
		if perception.Topic(text, d.patterns) {
			ev.labels = append(ev.labels, d.name)
		}
		return nil
	default:
		if len(d.patterns) == 0 {
			ev.info(layerAwareness, a.name, "unsupported detector "+d.name)
			return nil
		}
		return []detected{{detector: d.name, focus: d.focus, matches: perception.Custom(text, d.name, d.patterns)}}
	}
}

// byDetector splits the matches of an all-built-ins run by detector, in
// order of first appearance.
func byDetector(focus awareness.Focus, matches []perception.Match) []detected {
	var out []detected
	index := map[string]int{}
	for _, m := range matches {
		i, ok := index[m.Detector]
		if !ok {
			i = len(out)
			index[m.Detector] = i
			out = append(out, detected{detector: m.Detector, focus: focus})
		}
		out[i].matches = append(out[i].matches, m)
	}
	return out
}

// recordAwareness adds the finding for one detector's matches and queues
// their redaction when the awareness action redacts. vault redacts the
// same way and stores no token.
func (ev *evaluation) recordAwareness(ctx context.Context, e *Engine, a *compiledAwareness, f detected) {
	spans := mergeSpans(f.matches)
	score := 0.0
	for _, m := range f.matches {
		score = max(score, m.Score)
	}
	message, ok := awarenessMessages[f.focus]
	if !ok {
		message = "pattern matched"
	}
	ev.add(&scan.Finding{
		Layer: layerAwareness, Source: a.name, Message: message, Score: score, Action: a.action,
		Details: map[string]any{"detector": f.detector, "count": len(spans), "spans": spans},
	})
	redact := scan.ActionDecision(a.action) == scan.DecisionRedact
	switch f.focus {
	case awareness.FocusSecrets:
		ev.secretsFound = append(ev.secretsFound, f.matches...)
		if redact {
			ev.secrets = append(ev.secrets, f.matches...)
		}
	case awareness.FocusPII:
		ev.piiFound = append(ev.piiFound, f.matches...)
		if redact {
			ev.pii = append(ev.pii, f.matches...)
			ev.piiRedacted = append(ev.piiRedacted, piiTally{f.detector, len(spans)})
		}
		e.registry.EmitPIIDetected(ctx, ev.scanID, f.detector, len(spans))
	default:
		if redact {
			ev.custom = append(ev.custom, f.matches...)
		}
	}
}
