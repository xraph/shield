package engine

import (
	"maps"
	"slices"

	"github.com/xraph/shield/awareness"
	"github.com/xraph/shield/awareness/perception"
	"github.com/xraph/shield/id"
	"github.com/xraph/shield/instinct/detection"
	"github.com/xraph/shield/scan"
)

// removedInstruction replaces each line an instinct removes.
const removedInstruction = "[shield: removed suspected instruction]"

// redactedMask replaces each span a reflex redacts.
const redactedMask = "[REDACTED]"

// Finding layers.
const (
	layerInstinct  = "instinct"
	layerAwareness = "awareness"
	layerBoundary  = "boundary"
	layerValues    = "values"
	layerJudgment  = "judgment"
	layerReflex    = "reflex"
	layerPolicy    = "policy"
)

// actionInfo is the action of a finding that reports a configuration the
// engine cannot run. It never changes the decision.
const actionInfo = "info"

// actionBlock is the action of a finding that blocks.
const actionBlock = "block"

// scoreTolerance absorbs float rounding when a score is compared with a
// threshold, so a score computed as 0.7 reaches a threshold of 0.7.
const scoreTolerance = 1e-9

// evaluation is the working state of one scan as the layers run.
type evaluation struct {
	scanID  id.ScanID
	tenant  string
	app     string
	input   *scan.Input
	profile *compiledProfile

	folded     detection.Text
	haveFolded bool

	findings []*scan.Finding
	blocked  bool // a finding blocks

	// Redactions in the order Apply gives them precedence at an equal
	// start: removed instruction lines, then secrets, then personal data,
	// then other patterns, then reflex masks.
	removals []perception.Span
	secrets  []perception.Match
	pii      []perception.Match
	custom   []perception.Match
	masks    []perception.Span

	quote   bool    // an instinct asked for the whole text to be quoted
	rewrite *string // a reflex replaced the whole text

	// hits holds what each awareness finding matched, so a policy can
	// force its redaction.
	hits map[*scan.Finding]*awarenessHit

	// policiesUsed names the policies evaluated.
	policiesUsed []string

	// context is the on_context view of the input, built once.
	context map[string]string

	// Every match found, redacted or not, for counting.
	secretsFound []perception.Match
	piiFound     []perception.Match

	// piiRedacted tallies the personal data queued for redaction, by
	// detector, for the PIIRedacted hook once the scan is not blocked.
	piiRedacted []piiTally

	// labels are the topic detector names that matched, for boundaries.
	labels []string
}

// piiTally is a count of personal data values of one type.
type piiTally struct {
	typ   string
	count int
}

// foldedText returns the folded input, folding it once per scan.
func (ev *evaluation) foldedText() detection.Text {
	if !ev.haveFolded {
		ev.folded = detection.Fold(ev.input.Text)
		ev.haveFolded = true
	}
	return ev.folded
}

// awarenessHit is what one awareness finding matched.
type awarenessHit struct {
	focus    awareness.Focus
	detector string
	matches  []perception.Match
	redacted bool // queued for redaction
}

// add records a finding. Its severity follows from its action.
func (ev *evaluation) add(f *scan.Finding) {
	f.ID = id.NewFindingID()
	f.Severity = severity(f.Action)
	ev.findings = append(ev.findings, f)
	if scan.ActionDecision(f.Action) == scan.DecisionBlock {
		ev.blocked = true
	}
}

// detections returns the findings so far that report a detection, leaving
// out configuration notices.
func (ev *evaluation) detections() []*scan.Finding {
	out := make([]*scan.Finding, 0, len(ev.findings))
	for _, f := range ev.findings {
		if f.Action != actionInfo {
			out = append(out, f)
		}
	}
	return out
}

// info records a finding about configuration the engine cannot run.
func (ev *evaluation) info(layer, source, message string) {
	ev.add(&scan.Finding{Layer: layer, Source: source, Message: message, Action: actionInfo})
}

// severity maps an action to a finding severity: block is critical, redact
// is an error, flag is a warning and the rest are info.
func severity(action string) string {
	switch scan.ActionDecision(action) {
	case scan.DecisionBlock:
		return "critical"
	case scan.DecisionRedact:
		return "error"
	case scan.DecisionFlag:
		return "warning"
	default:
		return "info"
	}
}

// decide folds the findings into the result: the strictest action decides,
// Blocked follows a block, and Redacted is the text with every redaction
// applied (or a reflex's rewrite), quoted when the input is untrusted or an
// instinct asked for it. A blocked result carries no text, and trusted text
// that was not redacted carries none either.
func (ev *evaluation) decide(r *scan.Result) {
	decision := scan.DecisionAllow
	for _, f := range ev.findings {
		decision = scan.Stricter(decision, scan.ActionDecision(f.Action))
	}
	r.Decision = decision
	r.Blocked = decision == scan.DecisionBlock
	r.Findings = ev.findings
	r.Redacted = ""
	if r.Blocked {
		return
	}
	var text string
	if ev.rewrite != nil {
		text = *ev.rewrite
	} else {
		text = ev.redactedText()
	}
	switch {
	case ev.input.Untrusted || ev.quote:
		r.Redacted = scan.Quote(ev.input.Source, text)
	case decision == scan.DecisionRedact:
		r.Redacted = text
	}
}

// redactedText applies every redaction to the input. Overlapping spans
// merge into the first one by start, in removal, secret, personal data,
// pattern, mask order on a tie, as perception.Apply does. Placeholder numbers are
// given only to the matches that survive that merge, so a hidden overlap
// never uses up a number.
func (ev *evaluation) redactedText() string {
	type candidate struct {
		span    perception.Span
		match   perception.Match
		isMatch bool
	}
	cands := make([]candidate, 0, len(ev.removals)+len(ev.secrets)+len(ev.pii)+len(ev.custom)+len(ev.masks))
	for _, s := range ev.removals {
		cands = append(cands, candidate{span: s})
	}
	for _, group := range [][]perception.Match{ev.secrets, ev.pii, ev.custom} {
		for _, m := range group {
			cands = append(cands, candidate{span: perception.Span{Start: m.Start, End: m.End}, match: m, isMatch: true})
		}
	}
	for _, s := range ev.masks {
		cands = append(cands, candidate{span: s})
	}
	if len(cands) == 0 {
		return ev.input.Text
	}
	slices.SortStableFunc(cands, func(a, b candidate) int { return a.span.Start - b.span.Start })
	var spans []perception.Span
	var winners []perception.Match
	for i := 0; i < len(cands); {
		win := cands[i]
		end := win.span.End
		i++
		for i < len(cands) && cands[i].span.Start < end {
			end = max(end, cands[i].span.End)
			i++
		}
		if win.isMatch {
			win.match.End = end
			winners = append(winners, win.match)
			continue
		}
		win.span.End = end
		spans = append(spans, win.span)
	}
	spans = append(spans, perception.Placeholders(winners)...)
	return perception.Apply(ev.input.Text, spans)
}

// metadata is a copy of the input metadata plus the source, whether the
// text is untrusted and, when there were any, the number of secrets found.
func (ev *evaluation) metadata() map[string]any {
	md := make(map[string]any, len(ev.input.Metadata)+3)
	maps.Copy(md, ev.input.Metadata)
	if ev.input.Source != "" {
		md["source"] = ev.input.Source
	}
	md["untrusted"] = ev.input.Untrusted
	if n := countSpans(ev.secretsFound); n > 0 {
		md["secret_count"] = n
	}
	return md
}

// piiCount counts the personal data found, leaving out any value that is
// part of a secret.
func (ev *evaluation) piiCount() int {
	var kept []perception.Match
	for _, m := range ev.piiFound {
		if !overlapsAny(m, ev.secretsFound) {
			kept = append(kept, m)
		}
	}
	return countSpans(kept)
}

// mergeSpans returns the byte ranges the matches cover, overlapping ones
// merged, in order.
func mergeSpans(ms []perception.Match) [][2]int {
	if len(ms) == 0 {
		return nil
	}
	order := slices.Clone(ms)
	slices.SortFunc(order, func(a, b perception.Match) int { return a.Start - b.Start })
	out := [][2]int{{order[0].Start, order[0].End}}
	for _, m := range order[1:] {
		last := &out[len(out)-1]
		if m.Start < last[1] {
			last[1] = max(last[1], m.End)
			continue
		}
		out = append(out, [2]int{m.Start, m.End})
	}
	return out
}

// countSpans counts the distinct values the matches cover: overlapping
// matches count once.
func countSpans(ms []perception.Match) int { return len(mergeSpans(ms)) }

func overlapsAny(m perception.Match, others []perception.Match) bool {
	for _, o := range others {
		if m.Start < o.End && o.Start < m.End {
			return true
		}
	}
	return false
}
