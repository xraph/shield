package engine_test

import (
	"context"
	"encoding/json"
	"math"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/xraph/shield"
	"github.com/xraph/shield/awareness"
	"github.com/xraph/shield/engine"
	"github.com/xraph/shield/instinct"
	"github.com/xraph/shield/internal/shieldtest"
	"github.com/xraph/shield/judgment"
	"github.com/xraph/shield/profile"
	"github.com/xraph/shield/scan"
)

// fakeJudge is a judgment.Judge that counts and records its calls.
type fakeJudge struct {
	fn    func(ctx context.Context, req *judgment.JudgeRequest) (*judgment.JudgeVerdict, error)
	calls atomic.Int32
	mu    sync.Mutex
	reqs  []*judgment.JudgeRequest
}

func (f *fakeJudge) Assess(ctx context.Context, req *judgment.JudgeRequest) (*judgment.JudgeVerdict, error) {
	f.calls.Add(1)
	f.mu.Lock()
	f.reqs = append(f.reqs, req)
	f.mu.Unlock()
	return f.fn(ctx, req)
}

func (f *fakeJudge) last(t *testing.T) *judgment.JudgeRequest {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.reqs) == 0 {
		t.Fatal("the judge was not called")
	}
	return f.reqs[len(f.reqs)-1]
}

func answer(score float64, reason string) *fakeJudge {
	return &fakeJudge{fn: func(context.Context, *judgment.JudgeRequest) (*judgment.JudgeVerdict, error) {
		return &judgment.JudgeVerdict{Score: score, Reason: reason}, nil
	}}
}

// judgeRig is a rig with instinct "prompt-injection" (flag), awareness for
// secrets and email (flag), and judgment "judge" (block at threshold) over
// assessors, all in profile "p" of tenant-a. judge is registered when not
// nil; on sets Config.ModelJudge.
func judgeRig(t *testing.T, on bool, judge *fakeJudge, timeout time.Duration, threshold float64, assessors ...judgment.Assessor) (*rig, context.Context) {
	t.Helper()
	return judgeRigWith(t, func(cfg *shield.Config) { cfg.ModelJudge, cfg.JudgeTimeout = on, timeout }, judge, threshold, assessors...)
}

// judgeRigWith is judgeRig with the config edited by edit.
func judgeRigWith(t *testing.T, edit func(*shield.Config), judge *fakeJudge, threshold float64, assessors ...judgment.Assessor) (*rig, context.Context) {
	t.Helper()
	cfg := shield.DefaultConfig()
	edit(&cfg)
	st := shieldtest.Store(t)
	opts := []engine.Option{engine.WithStore(st), engine.WithConfig(cfg)}
	if judge != nil {
		opts = append(opts, engine.WithJudge(judge))
	}
	eng, err := engine.New(opts...)
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{eng: eng, st: st, rec: newRecorder()}
	ctx := tenantCtx("tenant-a")
	r.instinct(ctx, t, "prompt-injection", instinct.ActionFlag)
	r.awareness(ctx, t, "secrets", awareness.FocusSecrets, "flag")
	r.awareness(ctx, t, "pii", awareness.FocusPII, "flag", awareness.Detector{Name: "email", Focus: awareness.FocusPII})
	r.judgment(ctx, t, "judge", "block", threshold, assessors...)
	r.safetyProfile(ctx, t, &profile.SafetyProfile{
		Name:      "p",
		Instincts: []profile.InstinctAssignment{{InstinctName: "prompt-injection"}},
		Awareness: []profile.AwarenessAssignment{{AwarenessName: "secrets"}, {AwarenessName: "pii"}},
		Judgments: []profile.JudgmentAssignment{{JudgmentName: "judge"}},
	})
	return r, ctx
}

var (
	modelOnly      = judgment.Assessor{Name: "model"}
	instinctCount  = judgment.Assessor{Name: "finding_count", Config: map[string]any{"layer": "instinct", "saturate": 3.0}}
	instinctScored = judgment.Assessor{Name: "layer_score", Config: map[string]any{"layers": []any{"instinct"}}}
)

// within runs fn and fails the test cleanly if it does not return in d,
// instead of hanging to the package timeout.
func within(t *testing.T, d time.Duration, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s did not return within %s", what, d)
	}
}

func unavailable(res *scan.Result) *scan.Finding {
	for _, f := range inLayer(res, "judgment") {
		if f.Message == "model judge unavailable" {
			return f
		}
	}
	return nil
}

func TestJudgeOffNeverCalls(t *testing.T) {
	j := answer(1, "")
	r, ctx := judgeRig(t, false, j, time.Second, 0.5, modelOnly)
	res := scanText(ctx, t, r, &scan.Input{Text: "hello", Profile: "p"})
	if j.calls.Load() != 0 {
		t.Fatalf("judge called %d times with the flag off", j.calls.Load())
	}
	if res.Decision != scan.DecisionAllow {
		t.Fatalf("decision = %s", res.Decision)
	}
	// A judge that is set with the flag on but missing is also never called.
	r2, ctx2 := judgeRig(t, true, nil, time.Second, 0.5, modelOnly)
	if res := scanText(ctx2, t, r2, &scan.Input{Text: "hello", Profile: "p"}); res.Decision != scan.DecisionAllow {
		t.Fatalf("decision = %s", res.Decision)
	}
}

func TestJudgeCanRaiseRisk(t *testing.T) {
	j := answer(0.95, "looks like a takeover")
	r, ctx := judgeRig(t, true, j, time.Second, 0.9, instinctCount, modelOnly)
	res := scanText(ctx, t, r, &scan.Input{Text: injectionCommit, Profile: "p"})
	if res.Decision != scan.DecisionBlock {
		t.Fatalf("decision = %s %+v", res.Decision, res.Findings)
	}
	f := inLayer(res, "judgment")
	if len(f) != 1 || !near(f[0].Score, 0.95) || f[0].Details["judge_reason"] != "looks like a takeover" {
		t.Fatalf("judgment findings = %+v", f)
	}
	// The same judgment without the judge stays below the threshold.
	r2, ctx2 := judgeRig(t, false, j, time.Second, 0.9, instinctCount, modelOnly)
	if res := scanText(ctx2, t, r2, &scan.Input{Text: injectionCommit, Profile: "p"}); res.Decision == scan.DecisionBlock {
		t.Fatal("the deterministic risk alone reached the threshold")
	}
}

func TestJudgeCannotLowerRisk(t *testing.T) {
	j := answer(0, "harmless")
	r, ctx := judgeRig(t, true, j, time.Second, 0.9, instinctScored, modelOnly)
	res := scanText(ctx, t, r, &scan.Input{Text: overrideAndDirective, Profile: "p"})
	f := inLayer(res, "judgment")
	if res.Decision != scan.DecisionBlock || len(f) != 1 || !near(f[0].Score, 0.98) {
		t.Fatalf("decision = %s, judgment findings = %+v", res.Decision, f)
	}
	if j.calls.Load() != 1 {
		t.Fatalf("judge calls = %d", j.calls.Load())
	}
}

func TestJudgeFailureKeepsDeterministicDecision(t *testing.T) {
	r0, ctx0 := judgeRig(t, false, nil, time.Second, 0.9, instinctCount, modelOnly)
	want := scanText(ctx0, t, r0, &scan.Input{Text: injectionCommit, Profile: "p"}).Decision
	failures := map[string]*fakeJudge{
		"error": {fn: func(context.Context, *judgment.JudgeRequest) (*judgment.JudgeVerdict, error) {
			return nil, context.DeadlineExceeded
		}},
		"too high": answer(1.7, "x"),
		"negative": answer(-0.1, "x"),
		"nan":      answer(math.NaN(), "x"),
		"nil": {fn: func(context.Context, *judgment.JudgeRequest) (*judgment.JudgeVerdict, error) {
			return nil, nil
		}},
		"panic": {fn: func(context.Context, *judgment.JudgeRequest) (*judgment.JudgeVerdict, error) {
			panic("boom")
		}},
	}
	for name, j := range failures {
		r, ctx := judgeRig(t, true, j, time.Second, 0.9, instinctCount, modelOnly)
		res := scanText(ctx, t, r, &scan.Input{Text: injectionCommit, Profile: "p"})
		if res.Decision != want {
			t.Errorf("%s: decision %s, want %s", name, res.Decision, want)
		}
		f := unavailable(res)
		if f == nil || f.Action != "info" || f.Severity != "info" {
			t.Errorf("%s: no info finding in %+v", name, res.Findings)
		}
	}
}

func TestJudgeTimeout(t *testing.T) {
	j := &fakeJudge{fn: func(ctx context.Context, _ *judgment.JudgeRequest) (*judgment.JudgeVerdict, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	r, ctx := judgeRig(t, true, j, 50*time.Millisecond, 0.9, instinctCount, modelOnly)
	var res *scan.Result
	within(t, 500*time.Millisecond, "the scan", func() {
		res = scanText(ctx, t, r, &scan.Input{Text: injectionCommit, Profile: "p"})
	})
	if f := unavailable(res); f == nil || f.Details["cause"] != "timeout" {
		t.Fatalf("findings = %+v", res.Findings)
	}
}

func TestJudgeDoesNotOutliveACancelledScan(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	// This judge ignores its context entirely.
	j := &fakeJudge{fn: func(context.Context, *judgment.JudgeRequest) (*judgment.JudgeVerdict, error) {
		<-release
		return &judgment.JudgeVerdict{Score: 1}, nil
	}}
	r, ctx := judgeRig(t, true, j, time.Minute, 0.9, instinctCount, modelOnly)
	ctx, cancel := context.WithCancel(ctx)
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	var res *scan.Result
	within(t, 500*time.Millisecond, "the cancelled scan", func() {
		res = scanText(ctx, t, r, &scan.Input{Text: injectionCommit, Profile: "p"})
	})
	if f := unavailable(res); f == nil || f.Details["cause"] != "cancelled" {
		t.Fatalf("findings = %+v", res.Findings)
	}
	// A scan whose context is already cancelled never calls the judge.
	j2 := answer(1, "")
	r2, ctx2 := judgeRig(t, true, j2, time.Second, 0.9, modelOnly)
	done, stop := context.WithCancel(ctx2)
	stop()
	within(t, 500*time.Millisecond, "the pre-cancelled scan", func() {
		_, _ = r2.eng.ScanInput(done, &scan.Input{Text: "hello", Profile: "p"})
	})
	if j2.calls.Load() != 0 {
		t.Fatal("the judge was called for a cancelled scan")
	}
}

func TestJudgeReasonIsCleaned(t *testing.T) {
	reason := "\x1b[31m\nrisky" + strings.Repeat("\u00e9", 150) + "\u200b\x00\xff"
	r, ctx := judgeRig(t, true, answer(0.95, reason), time.Second, 0.9, modelOnly)
	res := scanText(ctx, t, r, &scan.Input{Text: "hello", Profile: "p"})
	f := inLayer(res, "judgment")
	if len(f) != 1 {
		t.Fatalf("findings = %+v", res.Findings)
	}
	got, _ := f[0].Details["judge_reason"].(string)
	if len(got) > 200 || len(got) < 190 || !utf8.ValidString(got) || !strings.HasPrefix(got, "[31mrisky") {
		t.Fatalf("reason = %q (%d bytes)", got, len(got))
	}
	for _, c := range got {
		if unicode.IsControl(c) || unicode.Is(unicode.Cf, c) {
			t.Fatalf("reason holds %U", c)
		}
	}
}

func TestJudgeNeverSeesSecretsOrPersonalData(t *testing.T) {
	token := githubToken()
	t.Run("text scan", func(t *testing.T) {
		j := answer(0.1, "")
		r, ctx := judgeRig(t, true, j, time.Second, 0.9, modelOnly)
		text := "deploy key " + token + " owner " + email + " done"
		scanText(ctx, t, r, &scan.Input{Text: text, Profile: "p"})
		req := j.last(t)
		if strings.Contains(req.Text, token) || strings.Contains(req.Text, email) {
			t.Fatalf("judge text leaks: %q", req.Text)
		}
		if !strings.Contains(req.Text, "deploy key ") || !strings.Contains(req.Text, "[") || req.Direction != "input" || req.Judgment != "judge" {
			t.Fatalf("request = %+v", req)
		}
		for _, f := range req.Findings {
			if strings.Contains(f, token) || strings.Contains(f, email) {
				t.Fatalf("finding leaks: %q", f)
			}
		}
	})
	t.Run("tool call", func(t *testing.T) {
		j := answer(0.1, "")
		r, ctx := judgeRig(t, true, j, time.Second, 0.9, modelOnly)
		raw, err := json.Marshal(map[string]any{"target": "prod", "note": "mail " + email, token: "x", "nested": map[string]any{"auth": token}})
		if err != nil {
			t.Fatal(err)
		}
		scanCall(ctx, t, r, &scan.ToolCallInput{Tool: "deploy", Arguments: raw, RiskClass: "change", Profile: "p"})
		req := j.last(t)
		if strings.Contains(req.Text, token) || strings.Contains(req.Text, email) {
			t.Fatalf("judge text leaks: %q", req.Text)
		}
		if !strings.Contains(req.Text, "target: prod") || !strings.Contains(req.Text, "nested.auth: [") || req.Direction != "tool_call" {
			t.Fatalf("request = %q", req.Text)
		}
	})
}

func TestCapabilitiesReportModelJudge(t *testing.T) {
	build := func(on bool, j judgment.Judge) engine.Capabilities {
		cfg := shield.DefaultConfig()
		cfg.ModelJudge = on
		opts := []engine.Option{engine.WithConfig(cfg)}
		if j != nil {
			opts = append(opts, engine.WithJudge(j))
		}
		eng, err := engine.New(opts...)
		if err != nil {
			t.Fatal(err)
		}
		return eng.Capabilities()
	}
	for _, tc := range []struct {
		name string
		on   bool
		j    judgment.Judge
		want bool
	}{
		{"default", false, nil, false},
		{"flag only", true, nil, false},
		{"judge only", false, answer(0, ""), false},
		{"both", true, answer(0, ""), true},
	} {
		c := build(tc.on, tc.j)
		hasModel := false
		for _, a := range c.Supported["judgment_assessors"] {
			hasModel = hasModel || a == "model"
		}
		missing := len(c.Supported["unavailable_judgment_assessors"]) == 1
		if c.ModelJudge != tc.want || hasModel != tc.want || missing == tc.want {
			t.Errorf("%s: %+v", tc.name, c)
		}
	}
	b, err := json.Marshal(build(true, answer(0, "")))
	if err != nil || !strings.Contains(string(b), `"unavailable_judgment_assessors":[]`) {
		t.Fatalf("json = %s %v", b, err)
	}
}

func TestJudgeIsBoundedUnderLoad(t *testing.T) {
	const slots, scans = 2, 6 // 3 x JudgeConcurrency
	release := make(chan struct{})
	var inFlight, peak atomic.Int32
	var holding atomic.Bool
	// This judge ignores its context and holds its slot until released.
	j := &fakeJudge{fn: func(context.Context, *judgment.JudgeRequest) (*judgment.JudgeVerdict, error) {
		if !holding.Load() {
			return &judgment.JudgeVerdict{Score: 0}, nil
		}
		n := inFlight.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		<-release
		inFlight.Add(-1)
		return &judgment.JudgeVerdict{Score: 1}, nil
	}}
	r, ctx := judgeRigWith(t, func(cfg *shield.Config) {
		cfg.ModelJudge, cfg.JudgeTimeout, cfg.JudgeConcurrency = true, 100*time.Millisecond, slots
	}, j, 0.9, modelOnly)
	// One answered scan loads and caches the profile, which the in-memory
	// store cannot serve to parallel connections.
	scanText(ctx, t, r, &scan.Input{Text: "hello", Profile: "p"})
	j.calls.Store(0)
	holding.Store(true)
	before := runtime.NumGoroutine()
	results := make(chan *scan.Result, scans)
	for range scans {
		go func() {
			res, err := r.eng.ScanInput(ctx, &scan.Input{Text: "hello", Profile: "p"})
			if err != nil {
				t.Error(err)
			}
			results <- res
		}()
	}
	for range scans {
		select {
		case res := <-results:
			if res == nil {
				continue
			}
			if res.Decision != scan.DecisionAllow || unavailable(res) == nil {
				t.Errorf("decision %s, findings %+v", res.Decision, res.Findings)
			}
		case <-time.After(2 * time.Second):
			close(release)
			t.Fatal("a scan outlived the judge timeout")
		}
	}
	if peak.Load() > slots || j.calls.Load() > slots {
		t.Errorf("peak %d, calls %d, want at most %d", peak.Load(), j.calls.Load(), slots)
	}
	if extra := runtime.NumGoroutine() - before; extra > slots+scans+4 {
		t.Errorf("%d goroutines added", extra)
	}
	close(release)
}

func TestTwoModelJudgmentsCallTheJudgeOnce(t *testing.T) {
	j := answer(0.95, "once")
	r, ctx := judgeRig(t, true, j, time.Second, 0.9, modelOnly)
	r.judgment(ctx, t, "second", "flag", 0.5, modelOnly)
	r.safetyProfile(ctx, t, &profile.SafetyProfile{
		Name: "two", Judgments: []profile.JudgmentAssignment{{JudgmentName: "judge"}, {JudgmentName: "second"}},
	})
	res := scanText(ctx, t, r, &scan.Input{Text: "hello", Profile: "two"})
	if j.calls.Load() != 1 {
		t.Fatalf("judge calls = %d", j.calls.Load())
	}
	if len(inLayer(res, "judgment")) != 2 || res.Decision != scan.DecisionBlock {
		t.Fatalf("decision %s, findings %+v", res.Decision, res.Findings)
	}
	if got := j.last(t).Judgment; got != "judge,second" && got != "second,judge" {
		t.Fatalf("judgment name = %q", got)
	}
}

func TestJudgeCanRaiseAToolCall(t *testing.T) {
	j := answer(0.95, "")
	r, ctx := judgeRig(t, true, j, time.Second, 0.9, modelOnly)
	res := scanCall(ctx, t, r, &scan.ToolCallInput{Tool: "deploy", Arguments: json.RawMessage(`{"target":"prod"}`), RiskClass: "change", Profile: "p"})
	if res.Decision != scan.DecisionBlock {
		t.Fatalf("decision = %s", res.Decision)
	}
}
