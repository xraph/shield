package engine

import (
	"context"
	"math"
	"regexp"
	"slices"
	"strings"

	"github.com/xraph/shield/instinct/detection"
	"github.com/xraph/shield/scan"
	"github.com/xraph/shield/values"
	"github.com/xraph/shield/values/principles"
)

// defaultValuesThreshold is the violation score of a rule with no
// threshold: one match.
const defaultValuesThreshold = 0.5

// defaultValuesSeverity is the severity of values with none set.
const defaultValuesSeverity = "warning"

// compiledValues is a values primitive ready to run.
type compiledValues struct {
	name     string
	action   string
	severity string
	rules    []compiledValueRule
}

// compiledValueRule is one rule with its detectors.
type compiledValueRule struct {
	principle values.Principle
	threshold float64
	lexicon   []*regexp.Regexp // built in, matched on the folded text
	patterns  []*regexp.Regexp // Config["patterns"], matched on the text as given
	terms     []string         // Config["terms"], folded, matched on the folded text

	lexiconScorer, patternScorer *principles.Scorer
}

func compileValues(v *values.Values) (*compiledValues, error) {
	cv := &compiledValues{name: v.Name, action: applicable(v.Action), severity: v.Severity}
	if cv.severity == "" {
		cv.severity = defaultValuesSeverity
	}
	for _, r := range v.Rules {
		cr := compiledValueRule{principle: r.Principle, threshold: r.Threshold, lexicon: principles.Lexicon(r.Principle, r.Categories)}
		if cr.threshold == 0 {
			cr.threshold = defaultValuesThreshold
		}
		sources, ok := stringList(r.Config["patterns"])
		if !ok {
			return nil, invalid("values", v.Name, "patterns must be a list of text")
		}
		for _, src := range sources {
			re, err := regexp.Compile(src)
			if err != nil {
				return nil, invalid("values", v.Name, "invalid pattern")
			}
			cr.patterns = append(cr.patterns, re)
		}
		terms, ok := stringList(r.Config["terms"])
		if !ok {
			return nil, invalid("values", v.Name, "terms must be a list of text")
		}
		for _, term := range terms {
			if folded := strings.TrimSpace(detection.Fold(term).Folded); folded != "" {
				cr.terms = append(cr.terms, folded)
			}
		}
		cr.lexiconScorer, cr.patternScorer = principles.NewScorer(cr.lexicon), principles.NewScorer(cr.patterns)
		cv.rules = append(cv.rules, cr)
	}
	return cv, nil
}

// runValues is layer 4. Each rule counts the matches of its detectors in
// each unit of the text: the built-in lexicon of its principle and
// categories and its literal terms (as whole words or phrases) on the
// folded unit, its own patterns on the unit as given. The score is the
// noisy-or of 0.5 per match (see principles.Score), and the rule is violated
// when the score reaches its threshold. A rule with no detector gives an
// info finding.
func (e *Engine) runValues(ctx context.Context, ev *evaluation) {
	for _, v := range ev.profile.values {
		for _, r := range v.rules {
			if len(r.lexicon) == 0 && len(r.patterns) == 0 && len(r.terms) == 0 {
				ev.info(layerValues, v.name, "no detector for principle "+string(r.principle))
				continue
			}
			n := 0
			var units []int
			for _, group := range ev.distinct {
				folded := ev.unitFolded(group[0]).Folded
				found := r.lexiconScorer.Count(folded) + r.patternScorer.Count(ev.unitText(group[0]))
				for _, term := range r.terms {
					found += countWords(folded, term, 0)
				}
				if found > 0 {
					n += found * len(group)
					units = append(units, group...)
				}
			}
			slices.Sort(units)
			score := 1 - math.Pow(0.5, float64(n))
			if n == 0 || score < r.threshold-scoreTolerance {
				continue
			}
			f := &scan.Finding{
				Layer: layerValues, Source: v.name, Message: "content violates the " + string(r.principle) + " principle",
				Score: score, Action: v.action, Details: map[string]any{"principle": string(r.principle), "count": n},
			}
			ev.add(f)
			ev.noteUnits(f, units)
			f.Severity = v.severity
			e.registry.EmitValueViolated(ctx, ev.scanID, v.name, v.severity)
		}
	}
}
