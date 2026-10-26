package engine

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xraph/shield/awareness/perception"
	"github.com/xraph/shield/reflex"
	"github.com/xraph/shield/scan"
)

// compiledReflex is a reflex with its triggers and actions parsed.
type compiledReflex struct {
	name     string
	priority int
	triggers []compiledTrigger
	actions  []compiledAction
	// unsupported names a trigger type the engine does not run. The reflex
	// then never fires and reports it as an info finding.
	unsupported string
}

// compiledTrigger is one trigger.
type compiledTrigger struct {
	kind      reflex.TriggerType
	pattern   *regexp.Regexp // on_pattern
	glob      string         // on_finding, on_score
	threshold float64        // on_score, on_rate
	context   []contextPair  // on_context
	window    time.Duration  // on_rate
}

// contextPair is one key=glob condition of an on_context trigger.
type contextPair struct{ key, glob string }

// compiledAction is one action with what it needs to apply.
type compiledAction struct {
	kind     string
	target   *regexp.Regexp // redact
	fallback string         // rewrite
}

func compileReflex(r *reflex.Reflex) (*compiledReflex, error) {
	cr := &compiledReflex{name: r.Name, priority: r.Priority}
	var onPattern *regexp.Regexp
	for _, t := range r.Triggers {
		ct := compiledTrigger{kind: t.Type, threshold: t.Threshold}
		switch t.Type {
		case reflex.TriggerOnPattern:
			re, err := regexp.Compile(t.Pattern)
			if err != nil {
				return nil, invalid("reflex", r.Name, "invalid pattern")
			}
			ct.pattern = re
			if onPattern == nil {
				onPattern = re
			}
		case reflex.TriggerOnFinding, reflex.TriggerOnScore:
			ct.glob = t.Pattern
		case reflex.TriggerOnContext:
			pairs, ok := parseContextPattern(t.Pattern)
			if !ok {
				return nil, invalid("reflex", r.Name, "invalid context pattern")
			}
			ct.context = pairs
		case reflex.TriggerOnRate:
			d, err := time.ParseDuration(t.Window)
			if err != nil || d <= 0 {
				return nil, invalid("reflex", r.Name, "invalid window")
			}
			ct.window = d
		case reflex.TriggerAlways:
		default:
			if cr.unsupported == "" {
				cr.unsupported = "unsupported trigger " + string(t.Type)
			}
		}
		cr.triggers = append(cr.triggers, ct)
	}
	for _, a := range r.Actions {
		ca := compiledAction{kind: string(a.Type), fallback: a.Fallback}
		switch a.Type {
		case reflex.ActionRedact:
			ca.target = onPattern
			if a.Target != "" {
				re, err := regexp.Compile(a.Target)
				if err != nil {
					return nil, invalid("reflex", r.Name, "invalid target")
				}
				ca.target = re
			}
			if ca.target == nil {
				// Nothing says what to redact: block rather than report
				// a redaction that changed nothing.
				ca.kind = actionBlock
			}
		case reflex.ActionRewrite:
			if a.Fallback == "" {
				ca.kind = actionBlock
			}
		default:
			ca.kind = applicable(ca.kind)
		}
		cr.actions = append(cr.actions, ca)
	}
	return cr, nil
}

// parseContextPattern reads comma-separated key=glob pairs. Every pair needs
// a key.
func parseContextPattern(s string) ([]contextPair, bool) {
	var pairs []contextPair
	for _, part := range strings.Split(s, ",") {
		key, glob, ok := strings.Cut(strings.TrimSpace(part), "=")
		key = strings.TrimSpace(key)
		if !ok || key == "" {
			return nil, false
		}
		pairs = append(pairs, contextPair{key: key, glob: strings.TrimSpace(glob)})
	}
	return pairs, true
}

// runReflexes is layer 6. Reflexes run by priority, highest first, then by
// name. A reflex fires when every one of its triggers matches; one without
// triggers never fires. Each action of a fired reflex adds a finding:
// redact masks its target's matches (or the on_pattern pattern's),
// rewrite replaces the whole text with the fallback, escalate flags, log is
// informational and throttle blocks.
func (e *Engine) runReflexes(ctx context.Context, ev *evaluation) {
	for _, r := range ev.profile.reflexes {
		if r.unsupported != "" {
			ev.info(layerReflex, r.name, r.unsupported)
			continue
		}
		if len(r.triggers) == 0 || !e.reflexTriggered(ev, r) {
			continue
		}
		for _, a := range r.actions {
			ev.applyReflexAction(r, a)
			e.registry.EmitReflexFired(ctx, ev.scanID, r.name, a.kind)
		}
	}
}

// reflexTriggered reports whether every trigger of r matches. Rate triggers
// are checked last, and the scan counts towards the rate only when every
// other trigger matched.
func (e *Engine) reflexTriggered(ev *evaluation, r *compiledReflex) bool {
	var rates []compiledTrigger
	for _, t := range r.triggers {
		if t.kind == reflex.TriggerOnRate {
			rates = append(rates, t)
			continue
		}
		if !ev.triggerMatches(t) {
			return false
		}
	}
	if len(rates) == 0 {
		return true
	}
	counts := e.rates.hit(rateKey{tenant: ev.tenant, app: ev.app, reflex: r.name}, time.Now(), rates)
	for i, t := range rates {
		if float64(counts[i]) <= t.threshold {
			return false
		}
	}
	return true
}

// triggerMatches evaluates one trigger other than on_rate.
func (ev *evaluation) triggerMatches(t compiledTrigger) bool {
	switch t.kind {
	case reflex.TriggerOnPattern:
		return t.pattern.MatchString(ev.input.Text)
	case reflex.TriggerOnFinding:
		for _, f := range ev.detections() {
			if globMatch(t.glob, f.Layer+":"+f.Source) {
				return true
			}
		}
		return false
	case reflex.TriggerOnScore:
		best := 0.0
		for _, f := range ev.detections() {
			if t.glob == "" || globMatch(t.glob, f.Layer) {
				best = max(best, f.Score)
			}
		}
		return best >= t.threshold-scoreTolerance
	case reflex.TriggerOnContext:
		values := ev.contextValues()
		for _, p := range t.context {
			v, ok := values[p.key]
			if !ok || !globMatch(p.glob, v) {
				return false
			}
		}
		return true
	case reflex.TriggerAlways:
		return true
	default:
		return false
	}
}

// contextValues are the string values of the input context plus the
// direction, source and untrusted flag of the scan, which win over context
// keys of the same name.
func (ev *evaluation) contextValues() map[string]string {
	out := make(map[string]string, len(ev.input.Context)+3)
	for k, v := range ev.input.Context {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	out["direction"] = string(ev.input.Direction)
	out["source"] = ev.input.Source
	out["untrusted"] = strconv.FormatBool(ev.input.Untrusted)
	return out
}

// applyReflexAction adds the finding of one action and makes its change.
func (ev *evaluation) applyReflexAction(r *compiledReflex, a compiledAction) {
	switch a.kind {
	case string(reflex.ActionRedact):
		for _, loc := range a.target.FindAllStringIndex(ev.input.Text, -1) {
			if loc[1] > loc[0] {
				ev.masks = append(ev.masks, perception.Span{Start: loc[0], End: loc[1], Placeholder: redactedMask})
			}
		}
	case string(reflex.ActionRewrite):
		if ev.rewrite == nil {
			fallback := a.fallback
			ev.rewrite = &fallback
		}
	}
	ev.add(&scan.Finding{
		Layer: layerReflex, Source: r.name, Message: "reflex fired", Action: a.kind,
		Details: map[string]any{"action": a.kind},
	})
}

// globMatch matches s against a pattern where * stands for any run of
// characters and ? for one.
func globMatch(pattern, s string) bool {
	p, n := []rune(pattern), []rune(s)
	pi, ni := 0, 0
	star, mark := -1, 0
	for ni < len(n) {
		switch {
		case pi < len(p) && (p[pi] == '?' || p[pi] == n[ni]):
			pi++
			ni++
		case pi < len(p) && p[pi] == '*':
			star, mark = pi, ni
			pi++
		case star >= 0:
			pi = star + 1
			mark++
			ni = mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}

// rateKey identifies the scans one reflex counts for a tenant and app.
type rateKey struct{ tenant, app, reflex string }

// rateLog is the recent scans one key counted, oldest first, and the
// longest window that looks at them.
type rateLog struct {
	times  []time.Time
	window time.Duration
}

// rateCounter remembers, in process, when each reflex's rate triggers
// counted a scan.
type rateCounter struct {
	mu   sync.Mutex
	logs map[rateKey]*rateLog
}

func newRateCounter() *rateCounter { return &rateCounter{logs: map[rateKey]*rateLog{}} }

// rateKeep bounds the timestamps kept per key, so a threshold above it never
// fires.
const rateKeep = 100000

// rateSweep is the number of keys above which a hit drops the keys whose
// scans have all left their window.
const rateSweep = 4096

// hit counts a scan at now for key and returns, for each trigger, the scans
// within its window, this one included. Only as many timestamps as the
// largest threshold needs are kept.
func (c *rateCounter) hit(key rateKey, now time.Time, triggers []compiledTrigger) []int {
	var window time.Duration
	keep := 1
	for _, t := range triggers {
		window = max(window, t.window)
		keep = max(keep, int(min(t.threshold, rateKeep))+1)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	recent, ok := c.logs[key]
	if !ok {
		recent = &rateLog{}
		c.logs[key] = recent
	}
	recent.window = window
	recent.times = append(recent.times, now)
	cut := 0
	for cut < len(recent.times) && !recent.times[cut].After(now.Add(-window)) {
		cut++
	}
	recent.times = recent.times[max(cut, len(recent.times)-keep):]
	counts := make([]int, len(triggers))
	for i, t := range triggers {
		from := now.Add(-t.window)
		for j := len(recent.times) - 1; j >= 0 && recent.times[j].After(from); j-- {
			counts[i]++
		}
	}
	if len(c.logs) > rateSweep {
		for k, l := range c.logs {
			if n := len(l.times); n == 0 || !l.times[n-1].After(now.Add(-l.window)) {
				delete(c.logs, k)
			}
		}
	}
	return counts
}
