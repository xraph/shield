package judgment

import "context"

// JudgeRequest is what a model judge is asked to assess.
//
// Text is never the scanned text as it came in: every secret and personal
// data span the awareness layer or shield's built-in detectors found is
// replaced by a placeholder first, whatever the profile does with those
// findings and even when it has no awareness, because the judge is a
// remote model. For a tool call it holds one "path: value" line per
// argument unit. Findings lists "<layer>:<source>" of the detections so
// far and carries no matched text.
type JudgeRequest struct {
	Text      string
	Direction string
	Judgment  string // judgment name
	Domain    Domain
	Findings  []string
}

// JudgeVerdict is a judge's answer. Score is a risk in [0,1]. Reason is
// untrusted model text. The engine never stores it: a judgment finding
// keeps the score only, as judge_score in its details.
type JudgeVerdict struct {
	Score  float64
	Reason string
}

// Judge assesses risk with a model. The engine calls it only when
// Config.ModelJudge is on, under the scan's context and Config.JudgeTimeout,
// and treats its answer as untrusted: the judgment's risk becomes the larger
// of the deterministic risk and the verdict's score, so a judge can raise a
// risk and never lower it. An error, a timeout or a score outside [0,1]
// leaves the deterministic result standing.
type Judge interface {
	Assess(ctx context.Context, req *JudgeRequest) (*JudgeVerdict, error)
}
