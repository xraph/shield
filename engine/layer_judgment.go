package engine

import (
	"context"
	"slices"

	"github.com/xraph/shield/judgment"
	"github.com/xraph/shield/scan"
)

// Judgment assessor names.
const (
	assessorLayerScore   = "layer_score"
	assessorFindingCount = "finding_count"
	assessorModel        = "model"
)

// defaultJudgmentThreshold is the risk at which a judgment with no threshold
// fires.
const defaultJudgmentThreshold = 0.7

// defaultSaturate is the finding count at which finding_count reaches 1.
const defaultSaturate = 3

// compiledJudgment is a judgment with its threshold resolved and its
// assessors parsed.
type compiledJudgment struct {
	name      string
	domain    judgment.Domain
	action    string
	threshold float64
	assessors []compiledAssessor
}

// compiledAssessor is one judgment assessor.
type compiledAssessor struct {
	name     string
	weight   float64  // 0 counts as 1
	layers   []string // layer_score: the layers whose findings count; empty is every layer
	layer    string   // finding_count: the layer counted; empty is every layer
	saturate int      // finding_count: the count that scores 1
}

// compileJudgment resolves the threshold (the profile's override, else the
// judgment's, else 0.7) and parses the assessors' config.
func compileJudgment(j *judgment.Judgment, override float64) (*compiledJudgment, error) {
	cj := &compiledJudgment{name: j.Name, domain: j.Domain, action: applicable(j.Action), threshold: j.Threshold}
	if override > 0 {
		cj.threshold = override
	}
	if cj.threshold == 0 {
		cj.threshold = defaultJudgmentThreshold
	}
	for _, a := range j.Assessors {
		ca := compiledAssessor{name: a.Name, weight: a.Weight}
		if ca.weight <= 0 {
			ca.weight = 1
		}
		switch a.Name {
		case assessorLayerScore:
			layers, ok := stringList(a.Config["layers"])
			if !ok {
				return nil, invalid("judgment", j.Name, "layers must be a list of text")
			}
			ca.layers = layers
		case assessorFindingCount:
			layer, ok := a.Config["layer"].(string)
			if a.Config["layer"] != nil && !ok {
				return nil, invalid("judgment", j.Name, "layer must be text")
			}
			ca.layer = layer
			n, ok := number(a.Config["saturate"])
			if !ok || n < 0 || n != float64(int(n)) {
				return nil, invalid("judgment", j.Name, "saturate must be a whole number")
			}
			ca.saturate = int(n)
			if ca.saturate == 0 {
				ca.saturate = defaultSaturate
			}
		}
		cj.assessors = append(cj.assessors, ca)
	}
	return cj, nil
}

// runJudgments is layer 5. A judgment's risk is the weighted mean of its
// deterministic assessors over the findings so far: layer_score is the
// highest finding score in its layers, finding_count is the number of
// findings in its layer over saturate, capped at 1. The model assessor asks
// the model judge when Config.ModelJudge is on and a judge is registered,
// once per scan however many judgments use it; otherwise it is skipped with an info finding, as is any
// unknown assessor. The judge is untrusted and only max() joins its score to
// the deterministic risk, so it can raise a risk and never lower it. A judge
// that fails, times out or answers outside [0,1] gives an info finding and
// the deterministic risk stands. The judge's reason is kept only on a
// judgment finding that fires. Every judgment reports its risk level; it
// fires when the risk reaches its threshold.
func (e *Engine) runJudgments(ctx context.Context, ev *evaluation) {
	for _, j := range ev.profile.judgments {
		sum, weights := 0.0, 0.0
		var verdict *judgment.JudgeVerdict
		asked := false
		for _, a := range j.assessors {
			var s float64
			switch a.name {
			case assessorLayerScore:
				for _, f := range ev.detections() {
					if len(a.layers) == 0 || slices.Contains(a.layers, f.Layer) {
						s = max(s, f.Score)
					}
				}
			case assessorFindingCount:
				count := 0
				for _, f := range ev.detections() {
					if a.layer == "" || f.Layer == a.layer {
						count++
					}
				}
				s = min(float64(count)/float64(a.saturate), 1)
			case assessorModel:
				switch {
				case !e.modelJudgeEnabled():
					ev.info(layerJudgment, j.name, "model assessor unavailable")
				case !asked:
					asked = true
					var cause string
					if verdict, cause = e.askJudge(ctx, ev); verdict == nil {
						ev.add(&scan.Finding{
							Layer: layerJudgment, Source: j.name, Message: "model judge unavailable", Action: actionInfo,
							Details: map[string]any{"cause": cause},
						})
					}
				}
				continue
			default:
				ev.info(layerJudgment, j.name, "unsupported assessor "+a.name)
				continue
			}
			sum += a.weight * s
			weights += a.weight
		}
		risk := 0.0
		if weights > 0 {
			risk = sum / weights
		}
		if verdict != nil {
			risk = max(risk, verdict.Score)
		}
		level := riskLevel(risk)
		if (weights > 0 || verdict != nil) && risk >= j.threshold-scoreTolerance {
			details := map[string]any{"risk_level": string(level), "threshold": j.threshold}
			if verdict != nil {
				details["judge_score"] = verdict.Score
				if reason := cleanReason(verdict.Reason); reason != "" {
					details["judge_reason"] = reason
				}
			}
			ev.add(&scan.Finding{
				Layer: layerJudgment, Source: j.name, Message: "risk reached the judgment threshold", Score: risk, Action: j.action,
				Details: details,
			})
		}
		e.registry.EmitJudgmentAssessed(ctx, ev.scanID, j.name, string(level), risk)
	}
}

// riskLevel buckets a risk score.
func riskLevel(risk float64) judgment.RiskLevel {
	switch {
	case risk < 0.2:
		return judgment.RiskNone
	case risk < 0.4:
		return judgment.RiskLow
	case risk < 0.6:
		return judgment.RiskMedium
	case risk < 0.8:
		return judgment.RiskHigh
	default:
		return judgment.RiskCritical
	}
}
