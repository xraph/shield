package engine

import (
	"context"
	"errors"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"go.opentelemetry.io/otel/attribute"

	"github.com/xraph/shield/awareness/perception"
	"github.com/xraph/shield/internal/telemetry"
	"github.com/xraph/shield/judgment"
)

// maxJudgeReasonBytes bounds the judge's reason in a finding's details.
const maxJudgeReasonBytes = 200

// Why a judge call gave no verdict. They are the cause detail of the
// "model judge unavailable" finding and the outcome of its span.
const (
	judgeError    = "error"
	judgeTimeout  = "timeout"
	judgeCancel   = "cancelled"
	judgeInvalid  = "invalid_verdict"
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

// askJudge asks the judge about j under the "assess with model judge" span,
// the scan's context and Config.JudgeTimeout. It returns the verdict, or a
// nil verdict and the cause when there is none. The judge is untrusted: a
// panic, an error, a nil verdict and a score outside [0,1] all count as no
// verdict, and a cancelled scan or a slow judge never holds the scan up.
func (e *Engine) askJudge(ctx context.Context, ev *evaluation, j *compiledJudgment) (verdict *judgment.JudgeVerdict, cause string) {
	ctx, span := telemetry.Tracer().Start(ctx, "assess with model judge")
	defer span.End()
	verdict, cause = e.callJudge(ctx, ev, j)
	span.SetAttributes(attribute.String("shield.judge.outcome", cause))
	if verdict == nil {
		telemetry.Fail(span, "judge_unavailable", errJudgeUnavailable)
	}
	return verdict, cause
}

func (e *Engine) callJudge(ctx context.Context, ev *evaluation, j *compiledJudgment) (verdict *judgment.JudgeVerdict, cause string) {
	if ctx.Err() != nil {
		return nil, judgeCancel
	}
	callCtx, cancel := context.WithTimeout(ctx, e.config.JudgeTimeout)
	defer cancel()
	req := &judgment.JudgeRequest{
		Text:      ev.judgeText(),
		Direction: string(ev.input.Direction),
		Judgment:  j.name,
		Domain:    j.domain,
		Findings:  ev.judgeFindings(),
	}
	// The channel holds the answer so a judge that ignores its context can
	// finish later without blocking on a send nobody reads.
	done := make(chan judgeAnswer, 1)
	go func() {
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
// placeholder in place of every secret and personal data span awareness
// found, whatever the profile does with them. A tool call gives one
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
// data match, offsets in the whole text. Overlapping matches merge into the
// first by start (a secret before personal data on a tie).
func (ev *evaluation) judgeSpans() []perception.Span {
	all := make([]perception.Match, 0, len(ev.secretsFound)+len(ev.piiFound))
	all = append(all, ev.secretsFound...)
	all = append(all, ev.piiFound...)
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

// cleanReason makes a judge's reason fit for a finding: invalid UTF-8,
// control and format characters are dropped, and the rest is cut to
// maxJudgeReasonBytes on a character boundary.
func cleanReason(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || !unicode.IsGraphic(r) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, ""))
	if len(s) <= maxJudgeReasonBytes {
		return s
	}
	cut := maxJudgeReasonBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}
