package engine

import (
	"context"
	"fmt"
	"slices"

	"github.com/xraph/shield"
	"github.com/xraph/shield/awareness"
	"github.com/xraph/shield/awareness/perception"
	"github.com/xraph/shield/policy"
	"github.com/xraph/shield/scan"
	"github.com/xraph/shield/store"
)

// defaultPolicyMessage is the finding message of a rule without an error
// message.
const defaultPolicyMessage = "policy rule matched"

// policyCheckTypes are the layers a rule can check.
var policyCheckTypes = []string{layerInstinct, layerAwareness, layerBoundary, layerValues, layerJudgment, layerReflex}

// compiledPolicyRule is one rule of an applicable policy.
type compiledPolicyRule struct {
	policy    string
	checkType string
	condition policy.Condition
	action    string
	message   string
	priority  int
}

// loadPolicies lists the enabled policies that apply to tenant: org-level
// policies keyed by the tenant, and app-level policies keyed by app that are
// assigned to the tenant. App-level policies are skipped when the store
// cannot report assignments or the app is empty.
func (e *Engine) loadPolicies(ctx context.Context, tenant, app string) ([]*policy.Policy, error) {
	org, err := e.store.GetPoliciesForScope(ctx, tenant, policy.ScopeOrg)
	if err != nil {
		return nil, fmt.Errorf("shield: load policies: %w", err)
	}
	out := slices.Clone(org)
	assignments, ok := e.store.(store.AssignmentStore)
	if !ok || app == "" {
		return out, nil
	}
	appLevel, err := e.store.GetPoliciesForScope(ctx, app, policy.ScopeApp)
	if err != nil {
		return nil, fmt.Errorf("shield: load policies: %w", err)
	}
	scope := store.Scope{TenantID: tenant, AppID: app}
	for _, p := range appLevel {
		assigned, assignedErr := assignments.DashboardAssigned(ctx, scope, p.ID.String())
		if assignedErr != nil {
			return nil, fmt.Errorf("shield: load policy assignment: %w", assignedErr)
		}
		if assigned {
			out = append(out, p)
		}
	}
	return out, nil
}

// compilePolicies parses the rules of the enabled policies and orders them by
// priority, highest first. A condition outside the grammar is
// ErrProfileInvalid.
func compilePolicies(policies []*policy.Policy) ([]string, []compiledPolicyRule, error) {
	var names []string
	var rules []compiledPolicyRule
	for _, p := range policies {
		if p == nil || !p.Enabled {
			continue
		}
		names = append(names, p.Name)
		for _, r := range p.Rules {
			cond, err := policy.ParseCondition(r.Condition)
			if err != nil {
				return nil, nil, fmt.Errorf("%w: policy %s: invalid condition", shield.ErrProfileInvalid, p.Name)
			}
			message := r.ErrorMessage
			if message == "" {
				message = defaultPolicyMessage
			}
			rules = append(rules, compiledPolicyRule{
				policy: p.Name, checkType: r.CheckType, condition: cond, action: r.Action, message: message, priority: r.Priority,
			})
		}
	}
	slices.SortStableFunc(rules, func(a, b compiledPolicyRule) int { return b.priority - a.priority })
	return names, rules, nil
}

// runPolicies is the last step: the tenant's policies, rule by rule in
// priority order, over every finding so far. A rule whose condition holds
// adds a finding with its action and error message. A redact rule forces
// the redaction of what the matching findings found, and blocks when they
// found nothing it can redact.
func (e *Engine) runPolicies(ctx context.Context, ev *evaluation) {
	decisions := make(map[string]scan.Decision, len(ev.profile.policies))
	for _, name := range ev.profile.policies {
		decisions[name] = scan.DecisionAllow
	}
	for _, r := range ev.profile.rules {
		matched, holds, known := ev.ruleMatches(r)
		if !known {
			ev.info(layerPolicy, r.policy, "unsupported check type "+r.checkType)
			continue
		}
		if !holds {
			continue
		}
		action := r.action
		if scan.ActionDecision(action) == scan.DecisionRedact && !ev.forceRedaction(matched) {
			action = actionBlock
		}
		ev.add(&scan.Finding{
			Layer: layerPolicy, Source: r.policy, Message: r.message, Action: action,
			Details: map[string]any{"check_type": r.checkType, "condition": r.condition.Kind},
		})
		decisions[r.policy] = scan.Stricter(decisions[r.policy], scan.ActionDecision(action))
	}
	for _, name := range ev.profile.policies {
		e.registry.EmitPolicyEvaluated(ctx, ev.scanID, name, string(decisions[name]))
	}
	ev.policiesUsed = ev.profile.policies
}

// ruleMatches evaluates a rule's condition. It returns the findings the
// condition matched, whether it holds, and whether the check type is one
// the engine knows. pii_detected and secret_detected look at awareness
// findings whatever the check type.
func (ev *evaluation) ruleMatches(r compiledPolicyRule) (matched []*scan.Finding, holds, known bool) {
	switch r.condition.Kind {
	case policy.ConditionPIIDetected, policy.ConditionSecretDetected:
		focus := awareness.FocusPII
		if r.condition.Kind == policy.ConditionSecretDetected {
			focus = awareness.FocusSecrets
		}
		for _, f := range ev.detections() {
			if hit := ev.hits[f]; hit != nil && hit.focus == focus {
				matched = append(matched, f)
			}
		}
		return matched, len(matched) > 0, true
	}
	if !slices.Contains(policyCheckTypes, r.checkType) {
		return nil, false, false
	}
	best := 0.0
	for _, f := range ev.detections() {
		if f.Layer != r.checkType {
			continue
		}
		best = max(best, f.Score)
		if r.condition.Kind == policy.ConditionFinding || r.condition.Holds(f.Score) {
			matched = append(matched, f)
		}
	}
	if r.condition.Kind == policy.ConditionFinding {
		return matched, len(matched) > 0, true
	}
	return matched, r.condition.Holds(best), true
}

// forceRedaction queues the redaction of what the findings found: the
// values an awareness finding matched and the lines an instinct finding
// matched. It reports whether there was anything to redact.
func (ev *evaluation) forceRedaction(findings []*scan.Finding) bool {
	redacts := false
	for _, f := range findings {
		if hit := ev.hits[f]; hit != nil {
			ev.redactHit(hit)
			redacts = true
			continue
		}
		spans, ok := f.Details["spans"].([][2]int)
		if f.Layer != layerInstinct || !ok {
			continue
		}
		for _, s := range spans {
			ev.removals = append(ev.removals, perception.Span{Start: s[0], End: s[1], Placeholder: removedInstruction})
			redacts = true
		}
	}
	return redacts
}
