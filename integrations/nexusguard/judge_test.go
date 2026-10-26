package nexusguard_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/xraph/nexus"
	"github.com/xraph/nexus/guard"
	"github.com/xraph/nexus/provider"

	"github.com/xraph/shield"
	"github.com/xraph/shield/engine"
	"github.com/xraph/shield/integrations/nexusguard"
	"github.com/xraph/shield/judgment"
	"github.com/xraph/shield/scan"
)

// reply returns a completion whose one choice says text.
func reply(text string) *provider.CompletionResponse {
	return &provider.CompletionResponse{Choices: []provider.Choice{{Message: provider.Message{Role: "assistant", Content: text}}}}
}

// recorder is a CompleteFunc that records each request and its context and
// answers with text.
type recorder struct {
	mu   sync.Mutex
	text string
	reqs []*provider.CompletionRequest
	ctxs []context.Context
}

func (r *recorder) complete(ctx context.Context, req *provider.CompletionRequest) (*provider.CompletionResponse, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reqs = append(r.reqs, req)
	r.ctxs = append(r.ctxs, ctx)
	return reply(r.text), nil
}

func (r *recorder) last(t *testing.T) (context.Context, *provider.CompletionRequest) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.reqs) == 0 {
		t.Fatal("the judge did not call CompleteFunc")
	}
	return r.ctxs[len(r.ctxs)-1], r.reqs[len(r.reqs)-1]
}

// requestText is everything a completion request would send the model.
func requestText(t *testing.T, req *provider.CompletionRequest) string {
	t.Helper()
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return req.System + "\n" + string(raw)
}

func judgeRequest() *judgment.JudgeRequest {
	return &judgment.JudgeRequest{Text: "deploy the thing", Direction: "input", Judgment: "model-check", Domain: judgment.DomainCustom}
}

func TestJudgeParsesVerdict(t *testing.T) {
	rec := &recorder{text: `{"score":0.8,"reason":"r"}`}
	v, err := nexusguard.NewJudge(rec.complete, "judge-model").Assess(context.Background(), judgeRequest())
	if err != nil {
		t.Fatal(err)
	}
	if v.Score != 0.8 || v.Reason != "r" {
		t.Errorf("verdict %+v", v)
	}
	_, req := rec.last(t)
	if req.Model != "judge-model" || req.MaxTokens != 200 || req.Provider != "" || req.Stream {
		t.Errorf("request %+v", req)
	}
	if req.System == "" || !strings.Contains(req.System, `"score"`) {
		t.Errorf("system prompt %q", req.System)
	}
	if len(req.Messages) != 1 || req.Messages[0].Role != "user" {
		t.Fatalf("messages %+v", req.Messages)
	}
	content, _ := req.Messages[0].Content.(string)
	if !strings.Contains(content, scan.Quote("judged_content", "deploy the thing")) {
		t.Errorf("content %q", content)
	}
}

func TestJudgeAcceptsAFencedVerdict(t *testing.T) {
	rec := &recorder{text: "```json\n{\"score\": 0, \"reason\": \"benign\"}\n```"}
	v, err := nexusguard.NewJudge(rec.complete, "m").Assess(context.Background(), judgeRequest())
	if err != nil || v.Score != 0 || v.Reason != "benign" {
		t.Errorf("verdict %+v, err %v", v, err)
	}
}

func TestJudgeProvider(t *testing.T) {
	rec := &recorder{text: `{"score":0.1,"reason":"ok"}`}
	if _, err := nexusguard.NewJudge(rec.complete, "m", nexusguard.WithJudgeProvider("anthropic")).Assess(context.Background(), judgeRequest()); err != nil {
		t.Fatal(err)
	}
	if _, req := rec.last(t); req.Provider != "anthropic" {
		t.Errorf("provider %q", req.Provider)
	}
}

func TestJudgeBadReplyIsAnError(t *testing.T) {
	for _, text := range []string{
		"not json",
		`{"score":2}`,
		`{"score":-0.1,"reason":"r"}`,
		`{"reason":"no score"}`,
		`{"score":"0.5","reason":"r"}`,
		`{"score":0.5,"reason":"r"} trailing`,
		`{"score":0.5,"reason":"r","extra":true}`,
		`[0.5]`,
		"",
	} {
		rec := &recorder{text: text}
		v, err := nexusguard.NewJudge(rec.complete, "m").Assess(context.Background(), judgeRequest())
		if err == nil {
			t.Errorf("%q: verdict %+v, want an error", text, v)
		}
		if err != nil && strings.Contains(err.Error(), "no score") {
			t.Errorf("%q: the error carries the reply: %v", text, err)
		}
	}
	empty := func(context.Context, *provider.CompletionRequest) (*provider.CompletionResponse, error) {
		return &provider.CompletionResponse{}, nil
	}
	if _, err := nexusguard.NewJudge(empty, "m").Assess(context.Background(), judgeRequest()); err == nil {
		t.Error("a reply with no choices is not an error")
	}
	failing := func(context.Context, *provider.CompletionRequest) (*provider.CompletionResponse, error) {
		return nil, errors.New("upstream down")
	}
	if _, err := nexusguard.NewJudge(failing, "m").Assess(context.Background(), judgeRequest()); err == nil {
		t.Error("a failed completion is not an error")
	}
}

func TestJudgeSkipsItsOwnGuard(t *testing.T) {
	r := newRig(t)
	rec := &recorder{text: `{"score":0.1,"reason":"ok"}`}
	if _, err := nexusguard.NewJudge(rec.complete, "m").Assess(tenantCtx(), judgeRequest()); err != nil {
		t.Fatal(err)
	}
	judgeCtx, _ := rec.last(t)
	in := &guard.CheckInput{Messages: []provider.Message{{Role: "user", Content: injectionLine}}, TenantID: testTenant}
	for _, g := range []guard.Guard{inputGuard(r), outputGuard(r)} {
		res, err := g.Check(judgeCtx, in)
		if err != nil {
			t.Fatal(err)
		}
		if !res.Passed || res.Modified || res.Blocked {
			t.Errorf("%s guard result %+v", g.Phase(), res)
		}
	}
	if n := len(r.scans(t)); n != 0 {
		t.Errorf("%d scans stored for the judge's own completion", n)
	}
}

// The skip marker is a private key type: no string-keyed value, whatever
// its name, turns scanning off.
func TestJudgeMarkerCannotBeForged(t *testing.T) {
	r := newRig(t)
	type otherKey string
	ctx := context.Background()
	for _, k := range []string{"nexusguard", "nexusguard.judge", "judge", "judgeCall", "judgeCallKey", "nexusguard_judge_call", "shield_judge", "skip_guard"} {
		ctx = context.WithValue(ctx, k, true) //nolint:revive,staticcheck // a plain string key is the forgery under test
		ctx = context.WithValue(ctx, otherKey(k), true)
	}
	res, err := inputGuard(r).Check(ctx, &guard.CheckInput{
		Messages: []provider.Message{{Role: "tool", Content: "3 pods ready"}}, TenantID: testTenant,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Modified {
		t.Errorf("result %+v", res)
	}
	if n := len(r.scans(t)); n != 1 {
		t.Errorf("%d scans stored, want 1", n)
	}
}

// The judge is a remote model: what CompleteFunc receives never holds a
// secret from the scanned text.
func TestJudgeSeesRedactedTextOnly(t *testing.T) {
	rec := &recorder{text: `{"score":0.2,"reason":"ok"}`}
	cfg := shield.DefaultConfig()
	cfg.ModelJudge = true
	r := newRig(t, engine.WithConfig(cfg), engine.WithJudge(nexusguard.NewJudge(rec.complete, "m")))
	r.judgedProfile(t)
	token := githubToken()
	res, err := inputGuard(r, nexusguard.WithProfile("judged")).Check(context.Background(), &guard.CheckInput{
		Messages: []provider.Message{{Role: "user", Content: "push with " + token + " now"}}, TenantID: testTenant,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Modified {
		t.Fatalf("result %+v", res)
	}
	_, req := rec.last(t)
	sent := requestText(t, req)
	if strings.Contains(sent, token) || strings.Contains(sent, "ghp_") {
		t.Errorf("the judge's request holds the token: %q", sent)
	}
	if !strings.Contains(sent, "push with [") {
		t.Errorf("the judge's request lacks the redacted text: %q", sent)
	}
	if n := len(r.scans(t)); n != 1 {
		t.Errorf("%d scans stored, want 1", n)
	}
}

func TestGatewayJudgeResolvesLazily(t *testing.T) {
	var gw *nexus.Gateway
	j := nexusguard.GatewayJudge(func() *nexus.Gateway { return gw }, "m")
	_, err := j.Assess(context.Background(), judgeRequest())
	if err == nil || !strings.Contains(err.Error(), "gateway") {
		t.Errorf("nil gateway: %v", err)
	}
	// A gateway that was never initialized has no engine yet.
	gw = nexus.New()
	_, err = j.Assess(context.Background(), judgeRequest())
	if err == nil || !strings.Contains(err.Error(), "gateway") {
		t.Errorf("uninitialized gateway: %v", err)
	}
	if _, err := nexusguard.GatewayJudge(nil, "m").Assess(context.Background(), judgeRequest()); err == nil {
		t.Error("nil resolver: no error")
	}
}
