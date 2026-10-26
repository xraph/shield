package engine

import (
	"context"
	"errors"
	"slices"
	"strings"

	"go.opentelemetry.io/otel/attribute"

	"github.com/xraph/shield/awareness/perception"
	"github.com/xraph/shield/internal/telemetry"
	"github.com/xraph/shield/judgment"
)

// Why a judge call gave no verdict. They are the cause detail of the
// "model judge unavailable" finding and the outcome of its span.
const (
	judgeError    = "error"
	judgeTimeout  = "timeout"
	judgeCancel   = "cancelled"
	judgeInvalid  = "invalid_verdict"
	judgeBusy     = "busy"
	judgeAnswered = "answered"
)

// errJudgeUnavailable marks the judge span failed. It carries no cause text
// so nothing the judge said reaches a span.
var errJudgeUnavailable = errors.New("shield: model judge unavailable")

// modelJudgeEnabled reports whether the model assessor can run: the flag is
// on and a judge is registered.
func (e *Engine) modelJudgeEnabled() bool { return e.config.ModelJudge && e.judge != nil }

// judgeAnswer is what the judge goroutine hands back.
type judgeAnswer struct {
	verdict *judgment.JudgeVerdict
	err     error
}

// askJudge returns the scan's judge verdict. The judge is called at most
// once per scan, whatever the number of judgments with a model assessor: the
// first call's outcome is reused by the rest.
func (e *Engine) askJudge(ctx context.Context, ev *evaluation) (verdict *judgment.JudgeVerdict, cause string) {
	if !ev.judged {
		ev.judged = true
		ev.judgeVerdict, ev.judgeCause = e.traceJudge(ctx, ev)
	}
	return ev.judgeVerdict, ev.judgeCause
}

// traceJudge makes the call under the "assess with model judge" span. The
// judge is untrusted: a panic, an error, a nil verdict and a score outside
// [0,1] all count as no verdict, and a cancelled scan, a slow judge or a
// full judge pool never holds the scan up.
func (e *Engine) traceJudge(ctx context.Context, ev *evaluation) (verdict *judgment.JudgeVerdict, cause string) {
	ctx, span := telemetry.Tracer().Start(ctx, "assess with model judge")
	defer span.End()
	verdict, cause = e.callJudge(ctx, ev)
	span.SetAttributes(attribute.String("shield.judge.outcome", cause))
	if verdict == nil {
		telemetry.Fail(span, "judge_unavailable", errJudgeUnavailable)
	}
	return verdict, cause
}

// judgeSubject names the judgments that use the model assessor, and their
// domain when they share one (custom otherwise). One judgment gives its own
// name; several give their names joined by commas.
func (ev *evaluation) judgeSubject() (name string, domain judgment.Domain) {
	var names []string
	for _, j := range ev.profile.judgments {
		if !slices.ContainsFunc(j.assessors, func(a compiledAssessor) bool { return a.name == assessorModel }) {
			continue
		}
		if len(names) == 0 {
			domain = j.domain
		} else if domain != j.domain {
			domain = judgment.DomainCustom
		}
		names = append(names, j.name)
	}
	return strings.Join(names, ","), domain
}

func (e *Engine) callJudge(ctx context.Context, ev *evaluation) (verdict *judgment.JudgeVerdict, cause string) {
	if ctx.Err() != nil {
		return nil, judgeCancel
	}
	callCtx, cancel := context.WithTimeout(ctx, e.config.JudgeTimeout)
	defer cancel()
	// A slot is held until the judge returns, even when the scan has given
	// up on it, so a judge that ignores its context can leak at most
	// JudgeConcurrency goroutines.
	select {
	case e.judgeSlots <- struct{}{}:
	case <-callCtx.Done():
		if ctx.Err() != nil {
			return nil, judgeCancel
		}
		return nil, judgeBusy
	}
	name, domain := ev.judgeSubject()
	req := &judgment.JudgeRequest{
		Text:      ev.judgeText(),
		Direction: string(ev.input.Direction),
		Judgment:  name,
		Domain:    domain,
		Findings:  ev.judgeFindings(),
	}
	// The channel holds the answer so a judge that ignores its context can
	// finish later without blocking on a send nobody reads.
	done := make(chan judgeAnswer, 1)
	go func() {
		defer func() { <-e.judgeSlots }()
		defer func() {
			if recover() != nil {
				done <- judgeAnswer{err: errJudgeUnavailable}
			}
		}()
		v, err := e.judge.Assess(callCtx, req)
		done <- judgeAnswer{verdict: v, err: err}
	}()
	select {
	case a := <-done:
		if a.err != nil {
			return nil, judgeError
		}
		if a.verdict == nil || !(a.verdict.Score >= 0 && a.verdict.Score <= 1) {
			return nil, judgeInvalid
		}
		return a.verdict, judgeAnswered
	case <-callCtx.Done():
		if ctx.Err() != nil {
			return nil, judgeCancel
		}
		return nil, judgeTimeout
	}
}

// judgeFindings lists "<layer>:<source>" of the detections so far.
func (ev *evaluation) judgeFindings() []string {
	found := ev.detections()
	out := make([]string, 0, len(found))
	for _, f := range found {
		out = append(out, f.Layer+":"+f.Source)
	}
	return out
}

// judgeText is the text the judge sees: the scanned text with a
// placeholder in place of every secret and personal data span, whatever the
// profile does with them. The spans are those awareness found merged with
// every built-in secret and personal data detector, so a profile with no
// awareness, or a narrowed one, still never sends a secret to the judge. A tool call gives one
// "path: value" line per argument unit, redacted the same way. It is only
// for the judge and is never scanned.
func (ev *evaluation) judgeText() string {
	spans := ev.judgeSpans()
	if ev.call == nil {
		return perception.Apply(ev.input.Text, spans)
	}
	lines := make([]string, 0, len(ev.units))
	for u, un := range ev.units {
		var local []perception.Span
		for _, s := range spans {
			if s.Start >= un.start && s.End <= un.end {
				s.Start -= un.start
				s.End -= un.start
				local = append(local, s)
			}
		}
		lines = append(lines, ev.unitPath(u)+": "+perception.Apply(ev.unitText(u), local))
	}
	return strings.Join(lines, "\n")
}

// judgeSpans returns the placeholder spans for every secret and personal
// data match, awareness's and the built-in detectors', offsets in the whole
// text. Overlapping matches merge into the first by start (a secret before
// personal data on a tie).
func (ev *evaluation) judgeSpans() []perception.Span {
	secrets, pii := ev.builtinMatches()
	all := make([]perception.Match, 0, len(ev.secretsFound)+len(secrets)+len(ev.piiFound)+len(pii))
	all = append(all, ev.secretsFound...)
	all = append(all, secrets...)
	all = append(all, ev.piiFound...)
	all = append(all, pii...)
	slices.SortStableFunc(all, func(a, b perception.Match) int { return a.Start - b.Start })
	var winners []perception.Match
	for i := 0; i < len(all); {
		win := all[i]
		end := win.End
		i++
		for i < len(all) && all[i].Start < end {
			end = max(end, all[i].End)
			i++
		}
		win.End = end
		winners = append(winners, win)
	}
	return perception.Placeholders(winners)
}

// builtinMatches runs every built-in secret and personal data detector over
// each unit, offsets in the whole text. Per unit, so no match spans two
// arguments of a tool call.
func (ev *evaluation) builtinMatches() (secrets, pii []perception.Match) {
	for u, un := range ev.units {
		text := ev.unitText(u)
		for _, m := range perception.Secrets(text, nil) {
			m.Start, m.End = m.Start+un.start, m.End+un.start
			secrets = append(secrets, m)
		}
		for _, m := range perception.PII(text, perception.BuiltinPII()) {
			m.Start, m.End = m.Start+un.start, m.End+un.start
			pii = append(pii, m)
		}
	}
	return secrets, pii
}
