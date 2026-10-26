package engine

import (
	"slices"

	"github.com/xraph/shield"
	"github.com/xraph/shield/awareness/perception"
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
	// instinct_strategies, awareness_detectors, judgment_assessors and
	// reflex_triggers.
	Supported map[string][]string `json:"supported"`
}

// Capabilities reports what this engine can do.
func (e *Engine) Capabilities() Capabilities {
	detectors := append(perception.BuiltinPII(), perception.BuiltinSecrets()...)
	slices.Sort(detectors)
	return Capabilities{
		Persistence: e.store != nil,
		Evaluation:  true,
		Layers:      []string{},
		Supported: map[string][]string{
			"instinct_strategies": {strategyCanary, strategyHeuristics, strategyPatterns},
			"awareness_detectors": detectors,
			"judgment_assessors":  {},
			"reflex_triggers":     {},
		},
	}
}

// Config returns a copy of the effective engine configuration.
func (e *Engine) Config() shield.Config { return e.config }
