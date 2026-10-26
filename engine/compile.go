package engine

import (
	"fmt"
	"regexp"
	"slices"

	"github.com/xraph/shield"
	"github.com/xraph/shield/awareness"
	"github.com/xraph/shield/awareness/perception"
	"github.com/xraph/shield/boundary"
	"github.com/xraph/shield/instinct"
	"github.com/xraph/shield/judgment"
	"github.com/xraph/shield/profile"
	"github.com/xraph/shield/reflex"
	"github.com/xraph/shield/values"
)

// Instinct strategy names the engine runs.
const (
	strategyPatterns   = "patterns"
	strategyHeuristics = "heuristics"
	strategyCanary     = "canary"
)

// compiledProfile is a safety profile with its primitives loaded, disabled
// ones dropped, regexes compiled and assignment overrides applied. It is
// immutable once built, so cached copies are shared across scans.
type compiledProfile struct {
	name       string
	instincts  []*compiledInstinct
	awareness  []*compiledAwareness
	boundaries []*boundary.Boundary
	values     []*values.Values
	judgments  []*compiledJudgment
	reflexes   []*reflex.Reflex
}

// compiledInstinct is an instinct ready to run.
type compiledInstinct struct {
	name       string
	category   instinct.Category
	action     string
	threshold  float64 // the effective sensitivity's Weight
	strategies []compiledStrategy
}

// compiledStrategy is one instinct strategy. An unsupported name runs as an
// info finding.
type compiledStrategy struct {
	name          string
	weight        float64 // 0 counts as 1
	patterns      []*regexp.Regexp
	patternWeight float64
	token         string
}

// compiledAwareness is an awareness primitive ready to run.
type compiledAwareness struct {
	name      string
	action    string
	detectors []compiledDetector
}

// compiledDetector is one awareness detector. builtin says the name is a
// built-in of its focus; all says it stands for every built-in of the focus
// (an awareness that lists no detectors).
type compiledDetector struct {
	name     string
	focus    awareness.Focus
	builtin  bool
	all      bool
	patterns []*regexp.Regexp
}

// compiledJudgment is a judgment with its profile threshold override applied.
type compiledJudgment struct {
	judgment  *judgment.Judgment
	threshold float64
}

// profileRows holds the enabled rows a profile references, by name.
type profileRows struct {
	instincts  map[string]*instinct.Instinct
	awareness  map[string]*awareness.Awareness
	boundaries map[string]*boundary.Boundary
	values     map[string]*values.Values
	judgments  map[string]*judgment.Judgment
	reflexes   map[string]*reflex.Reflex
}

// invalid reports a broken reference or setting of one primitive.
func invalid(kind, name, why string) error {
	if why == "" {
		return fmt.Errorf("%w: %s %s", shield.ErrProfileInvalid, kind, name)
	}
	return fmt.Errorf("%w: %s %s: %s", shield.ErrProfileInvalid, kind, name, why)
}

// compileProfile builds the compiled form of p from rows. A nil entry in a
// rows map is a disabled primitive and is skipped.
func compileProfile(p *profile.SafetyProfile, rows *profileRows) (*compiledProfile, error) {
	out := &compiledProfile{name: p.Name}
	for _, a := range p.Instincts {
		inst := rows.instincts[a.InstinctName]
		if inst == nil {
			continue
		}
		ci, err := compileInstinct(inst, a.Sensitivity)
		if err != nil {
			return nil, err
		}
		out.instincts = append(out.instincts, ci)
	}
	for _, a := range p.Awareness {
		aw := rows.awareness[a.AwarenessName]
		if aw == nil {
			continue
		}
		ca, err := compileAwareness(aw)
		if err != nil {
			return nil, err
		}
		out.awareness = append(out.awareness, ca)
	}
	for _, name := range p.Boundaries {
		if b := rows.boundaries[name]; b != nil {
			out.boundaries = append(out.boundaries, b)
		}
	}
	for _, name := range p.Values {
		if v := rows.values[name]; v != nil {
			out.values = append(out.values, v)
		}
	}
	for _, a := range p.Judgments {
		j := rows.judgments[a.JudgmentName]
		if j == nil {
			continue
		}
		threshold := j.Threshold
		if a.Threshold > 0 {
			threshold = a.Threshold
		}
		out.judgments = append(out.judgments, &compiledJudgment{judgment: j, threshold: threshold})
	}
	for _, name := range p.Reflexes {
		if r := rows.reflexes[name]; r != nil {
			out.reflexes = append(out.reflexes, r)
		}
	}
	return out, nil
}

// compileInstinct applies the sensitivity override and compiles strategies.
// No strategies means patterns plus heuristics.
func compileInstinct(inst *instinct.Instinct, override instinct.Sensitivity) (*compiledInstinct, error) {
	sensitivity := inst.Sensitivity
	if override != "" {
		sensitivity = override
	}
	ci := &compiledInstinct{name: inst.Name, category: inst.Category, action: inst.Action, threshold: sensitivity.Weight()}
	strategies := inst.Strategies
	if len(strategies) == 0 {
		strategies = []instinct.Strategy{{Name: strategyPatterns}, {Name: strategyHeuristics}}
	}
	for _, s := range strategies {
		cs := compiledStrategy{name: s.Name, weight: s.Weight}
		if cs.weight == 0 {
			cs.weight = 1
		}
		switch s.Name {
		case strategyPatterns:
			sources, ok := stringList(s.Config["patterns"])
			if !ok {
				return nil, invalid("instinct", inst.Name, "patterns must be a list of text")
			}
			for _, src := range sources {
				re, err := regexp.Compile(src)
				if err != nil {
					return nil, invalid("instinct", inst.Name, "invalid pattern")
				}
				cs.patterns = append(cs.patterns, re)
			}
			w, ok := number(s.Config["weight"])
			if !ok {
				return nil, invalid("instinct", inst.Name, "weight must be a number")
			}
			cs.patternWeight = w
		case strategyCanary:
			token, ok := s.Config["token"].(string)
			if s.Config["token"] != nil && !ok {
				return nil, invalid("instinct", inst.Name, "token must be text")
			}
			cs.token = token
		}
		ci.strategies = append(ci.strategies, cs)
	}
	return ci, nil
}

// compileAwareness compiles detector patterns. An awareness that lists no
// detectors runs every built-in of its focus.
func compileAwareness(a *awareness.Awareness) (*compiledAwareness, error) {
	ca := &compiledAwareness{name: a.Name, action: a.Action}
	if len(a.Detectors) == 0 {
		ca.detectors = []compiledDetector{{name: string(a.Focus), focus: a.Focus, all: true,
			builtin: a.Focus == awareness.FocusPII || a.Focus == awareness.FocusSecrets}}
		return ca, nil
	}
	for _, d := range a.Detectors {
		cd := compiledDetector{name: d.Name, focus: d.Focus}
		if cd.focus == "" {
			cd.focus = a.Focus
		}
		switch cd.focus {
		case awareness.FocusPII:
			cd.builtin = slices.Contains(perception.BuiltinPII(), d.Name)
		case awareness.FocusSecrets:
			cd.builtin = slices.Contains(perception.BuiltinSecrets(), d.Name)
		}
		for _, src := range d.Patterns {
			re, err := regexp.Compile(src)
			if err != nil {
				return nil, invalid("awareness", a.Name, "invalid pattern")
			}
			cd.patterns = append(cd.patterns, re)
		}
		ca.detectors = append(ca.detectors, cd)
	}
	return ca, nil
}

// stringList reads a JSON list of strings. Absent is an empty list.
func stringList(v any) ([]string, bool) {
	switch list := v.(type) {
	case nil:
		return nil, true
	case []string:
		return list, true
	case []any:
		out := make([]string, 0, len(list))
		for _, item := range list {
			s, ok := item.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	default:
		return nil, false
	}
}

// number reads a JSON number. Absent is zero.
func number(v any) (float64, bool) {
	switch n := v.(type) {
	case nil:
		return 0, true
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	default:
		return 0, false
	}
}
