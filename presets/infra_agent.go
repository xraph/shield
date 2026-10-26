package presets

import (
	"github.com/xraph/shield/awareness"
	"github.com/xraph/shield/boundary"
	"github.com/xraph/shield/instinct"
	"github.com/xraph/shield/judgment"
	"github.com/xraph/shield/policy"
	"github.com/xraph/shield/profile"
	"github.com/xraph/shield/reflex"
	"github.com/xraph/shield/values"
)

// The InfraAgent safety profiles, one per way an infra agent host uses
// shield: InfraAgentInput for untrusted content entering the model's
// context (scan.Input.Untrusted with a Source), InfraAgentOutput for text
// the agent sends out, InfraAgentTools for proposed tool calls.
const (
	InfraAgentInput  = "infra-agent-input"
	InfraAgentOutput = "infra-agent-output"
	InfraAgentTools  = "infra-agent-tools"
)

// Risk classes the InfraAgent tool profile understands. Hosts put one in ToolCallInput.RiskClass.
//
// The tools profile blocks a call with no class, asks a person to approve
// RiskDestroyProduction and RiskSecretOrExternal, and allows the rest unless
// the arguments carry a secret or an instruction. RiskPromoteProduction is
// allowed on purpose: the host's own autonomy gate decides it.
const (
	RiskRead                = "read"
	RiskChange              = "change"
	RiskDeployNonProduction = "deploy_nonproduction"
	RiskPromoteProduction   = "promote_production"
	RiskDestroyProduction   = "destroy_production"
	RiskSecretOrExternal    = "secret_or_external" // #nosec G101 -- a risk class name, not a credential
)

// Names of the InfraAgent primitives and policy.
const (
	infraAgent              = "infra-agent"
	promptInjection         = "prompt-injection"
	jailbreak               = "jailbreak"
	instructionExfiltration = "instruction-exfiltration"
	approvalManipulation    = "approval-manipulation"
	secretsAwareness        = "secrets"
	piiAwareness            = "pii"
	agentActions            = "agent-actions"
	destructiveCommands     = "destructive-commands"
	injectionPressure       = "injection-pressure"
	approveDestructive      = "approve-destructive"
	approveSecretOrExternal = "approve-secret-or-external"
	infraAgentBaseline      = "infra-agent-baseline"
)

// InfraAgent returns the safety preset for an infrastructure agent that
// reads commit messages, build logs, READMEs and issue bodies, writes issues
// and notifications, and proposes tool calls. Every call builds fresh rows,
// so changing one never changes another call's.
//
// Instruction-shaped text is removed line by line and secrets are always
// redacted, on every profile; personal data is redacted on input and output.
// Output also flags destructive commands, input flags a strong injection
// signal, and tool calls follow the risk classes above.
func InfraAgent() Bundle {
	instincts := []*instinct.Instinct{
		{
			Name: promptInjection, Description: "Removes lines that try to override instructions or address the agent.",
			Category:    instinct.CategoryInjection,
			Strategies:  []instinct.Strategy{{Name: "patterns"}, {Name: "heuristics"}},
			Sensitivity: instinct.SensitivityBalanced, Action: instinct.ActionRedact, Enabled: true,
		},
		{
			Name: jailbreak, Description: "Removes known jailbreak framings and role changes.",
			Category:    instinct.CategoryJailbreak,
			Strategies:  []instinct.Strategy{{Name: "patterns"}},
			Sensitivity: instinct.SensitivityBalanced, Action: instinct.ActionRedact, Enabled: true,
		},
		{
			Name: instructionExfiltration, Description: "Removes requests for the prompt, secrets or an upload of data.",
			Category:    instinct.CategoryExfiltration,
			Strategies:  []instinct.Strategy{{Name: "patterns"}},
			Sensitivity: instinct.SensitivityBalanced, Action: instinct.ActionRedact, Enabled: true,
		},
		{
			Name: approvalManipulation, Description: "Removes claims of approval and pushes to skip a safety step.",
			Category:    instinct.CategoryManipulation,
			Strategies:  []instinct.Strategy{{Name: "patterns"}},
			Sensitivity: instinct.SensitivityCautious, Action: instinct.ActionRedact, Enabled: true,
		},
	}
	aware := []*awareness.Awareness{
		{
			// No detectors means every built-in secret detector, including
			// any added later.
			Name: secretsAwareness, Description: "Redacts API keys, tokens, private keys and passwords.",
			Focus: awareness.FocusSecrets, Action: string(awareness.PIIActionRedact), Enabled: true,
		},
		{
			Name: piiAwareness, Description: "Redacts email addresses, phone numbers, SSNs, card numbers and IBANs.",
			Focus: awareness.FocusPII,
			Detectors: []awareness.Detector{
				{Name: "email", Focus: awareness.FocusPII},
				{Name: "phone", Focus: awareness.FocusPII},
				{Name: "ssn", Focus: awareness.FocusPII},
				{Name: "credit_card", Focus: awareness.FocusPII},
				{Name: "iban", Focus: awareness.FocusPII},
			},
			Action: string(awareness.PIIActionRedact), Enabled: true,
		},
	}
	boundaries := []*boundary.Boundary{
		{
			Name: agentActions, Description: "Blocks a tool call that names no risk class.",
			Limits:   []boundary.Limit{{Scope: boundary.ScopeAction, Deny: []string{"risk:unknown"}}},
			Response: "This tool call has no risk class, so it cannot run.", Enabled: true,
		},
	}
	vals := []*values.Values{
		{
			Name: destructiveCommands, Description: "Flags destructive infrastructure commands in outbound text.",
			Rules:    []values.Rule{{Principle: values.PrincipleSafety, Threshold: 0.5}},
			Severity: "warning", Action: "flag", Enabled: true,
		},
	}
	judgments := []*judgment.Judgment{
		{
			Name: injectionPressure, Description: "Flags input whose strongest instinct finding is near certain.",
			Domain: judgment.DomainCustom,
			Assessors: []judgment.Assessor{
				{Name: "layer_score", Domain: judgment.DomainCustom, Config: map[string]any{"layers": []any{"instinct"}}},
			},
			Threshold: 0.9, Action: "flag", Enabled: true,
		},
	}
	reflexes := []*reflex.Reflex{
		{
			Name: approveDestructive, Description: "Asks a person to approve a call that destroys production.",
			Triggers: []reflex.Trigger{{Type: reflex.TriggerOnContext, Pattern: "risk_class=" + RiskDestroyProduction}},
			Actions:  []reflex.Action{{Type: reflex.ActionEscalate}},
			Enabled:  true,
		},
		{
			Name: approveSecretOrExternal, Description: "Asks a person to approve a call that touches secrets or an outside system.",
			Triggers: []reflex.Trigger{{Type: reflex.TriggerOnContext, Pattern: "risk_class=" + RiskSecretOrExternal}},
			Actions:  []reflex.Action{{Type: reflex.ActionEscalate}},
			Enabled:  true,
		},
	}
	instinctAssignments := func() []profile.InstinctAssignment {
		return []profile.InstinctAssignment{
			{InstinctName: promptInjection},
			{InstinctName: jailbreak},
			{InstinctName: instructionExfiltration},
			{InstinctName: approvalManipulation},
		}
	}
	profiles := []*profile.SafetyProfile{
		{
			Name: InfraAgentInput, Description: "Untrusted content entering the agent's context.",
			Instincts: instinctAssignments(),
			Awareness: []profile.AwarenessAssignment{{AwarenessName: secretsAwareness}, {AwarenessName: piiAwareness}},
			Judgments: []profile.JudgmentAssignment{{JudgmentName: injectionPressure}},
			Enabled:   true,
		},
		{
			Name: InfraAgentOutput, Description: "Text the agent sends out: issue bodies, notifications and replies.",
			Awareness: []profile.AwarenessAssignment{{AwarenessName: secretsAwareness}, {AwarenessName: piiAwareness}},
			Values:    []string{destructiveCommands},
			Enabled:   true,
		},
		{
			Name: InfraAgentTools, Description: "Tool calls the agent proposes, after the host's risk table.",
			Instincts:  instinctAssignments(),
			Awareness:  []profile.AwarenessAssignment{{AwarenessName: secretsAwareness}},
			Boundaries: []string{agentActions},
			Reflexes:   []string{approveDestructive, approveSecretOrExternal},
			Enabled:    true,
		},
	}
	policies := []*policy.Policy{
		{
			Name: infraAgentBaseline, Description: "Redacts any secret a scan of the workspace finds.",
			ScopeLevel: policy.ScopeOrg,
			Rules: []policy.Rule{
				{CheckType: "awareness", Condition: policy.ConditionSecretDetected, Action: "redact"},
			},
			Enabled: true,
		},
	}
	return Bundle{
		Name:       infraAgent,
		Instincts:  instincts,
		Awareness:  aware,
		Boundaries: boundaries,
		Values:     vals,
		Judgments:  judgments,
		Reflexes:   reflexes,
		Profiles:   profiles,
		Policies:   policies,
	}
}
