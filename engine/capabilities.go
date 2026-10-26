package engine

import (
	"slices"

	"github.com/xraph/shield"
	"github.com/xraph/shield/awareness/perception"
	"github.com/xraph/shield/reflex"
	"github.com/xraph/shield/values"
)

// Capabilities describes implemented services, independently of configured rows.
type Capabilities struct {
	Persistence      bool `json:"persistence"`
	Evaluation       bool `json:"evaluation"`
	ToolCalls        bool `json:"tool_calls"`
	ModelJudge       bool `json:"model_judge"`
	ReportGeneration bool `json:"report_generation"`
	ConfigWrite      bool `json:"config_write"`
	// Layers lists the layers that cannot run. It is empty, never nil.
	Layers []string `json:"unavailable_layers"`
	// Supported names what the engine runs, sorted, under the keys
	// instinct_strategies, awareness_detectors, judgment_assessors,
	// reflex_triggers and values_lexicons (the principles with a built-in
	// detector). unavailable_judgment_assessors names the assessors a
	// judgment may list that the engine skips: model, unless
	// Config.ModelJudge is on and a judge is registered.
	Supported map[string][]string `json:"supported"`
}

// Capabilities reports what this engine can do.
func (e *Engine) Capabilities() Capabilities {
	detectors := append(perception.BuiltinPII(), perception.BuiltinSecrets()...)
	slices.Sort(detectors)
	assessors, unavailable := []string{assessorFindingCount, assessorLayerScore}, []string{assessorModel}
	modelJudge := e.modelJudgeEnabled()
	if modelJudge {
		assessors, unavailable = []string{assessorFindingCount, assessorLayerScore, assessorModel}, []string{}
	}
	return Capabilities{
		Persistence: e.store != nil,
		Evaluation:  true,
		ToolCalls:   true,
		ModelJudge:  modelJudge,
		Layers:      []string{},
		Supported: map[string][]string{
			"instinct_strategies": {strategyCanary, strategyHeuristics, strategyPatterns},
			"awareness_detectors": detectors,
			"judgment_assessors":  assessors,
			"reflex_triggers": {
				string(reflex.TriggerAlways), string(reflex.TriggerOnContext), string(reflex.TriggerOnFinding),
				string(reflex.TriggerOnPattern), string(reflex.TriggerOnRate), string(reflex.TriggerOnScore),
			},
			"values_lexicons":                {string(values.PrincipleSafety), string(values.PrincipleToxicity)},
			"unavailable_judgment_assessors": unavailable,
		},
	}
}

// Config returns a copy of the effective engine configuration.
func (e *Engine) Config() shield.Config { return e.config }
