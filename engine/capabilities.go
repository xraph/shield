package engine

import "github.com/xraph/shield"

// Capabilities describes implemented services, independently of configured rows.
type Capabilities struct {
	Persistence      bool     `json:"persistence"`
	Evaluation       bool     `json:"evaluation"`
	ReportGeneration bool     `json:"report_generation"`
	ConfigWrite      bool     `json:"config_write"`
	Layers           []string `json:"unavailable_layers"`
}

func (e *Engine) Capabilities() Capabilities {
	return Capabilities{Persistence: e.store != nil, Layers: []string{"instincts", "awareness", "boundaries", "values", "judgments", "reflexes"}}
}

// Config returns a copy of the effective engine configuration.
func (e *Engine) Config() shield.Config { return e.config }
