package redteam_test

import (
	"strings"
	"testing"

	"github.com/xraph/shield/instinct"
	"github.com/xraph/shield/instinct/detection"
	"github.com/xraph/shield/internal/scoring"
	"github.com/xraph/shield/redteam"
)

// threshold is the balanced instinct sensitivity.
const threshold = 0.6

var sources = []string{
	redteam.SourceCommitMessage,
	redteam.SourceLogLine,
	redteam.SourceReadme,
	redteam.SourceIssueBody,
}

// scan runs every pattern category and the heuristics over text, the way the
// preset instincts see it, and folds the families into one noisy-or score.
func scan(text string) (float64, []detection.Match) {
	folded := detection.Fold(text)
	results := []detection.Result{
		detection.Heuristics(folded),
		detection.Patterns(folded, instinct.CategoryInjection, nil, 0),
		detection.Patterns(folded, instinct.CategoryJailbreak, nil, 0),
		detection.Patterns(folded, instinct.CategoryExfiltration, nil, 0),
		detection.Patterns(folded, instinct.CategoryManipulation, nil, 0),
	}
	best := map[detection.Family]float64{}
	var matches []detection.Match
	for _, r := range results {
		for _, m := range r.Matches {
			best[m.Family] = max(best[m.Family], m.Weight)
			matches = append(matches, m)
		}
	}
	weights := make([]float64, 0, len(best))
	for _, w := range best {
		weights = append(weights, w)
	}
	return scoring.NoisyOr(weights...), matches
}

func TestFixtureSetCoverage(t *testing.T) {
	all := redteam.All()
	ids := map[string]bool{}
	techniqueSources := map[string]map[string]bool{}
	for _, f := range all {
		if ids[f.ID] {
			t.Errorf("duplicate fixture id %q", f.ID)
		}
		ids[f.ID] = true
		if f.Kind == "attack" {
			if f.Marker == "" || !strings.Contains(f.Text, f.Marker) {
				t.Errorf("%s: marker %q is not in the text", f.ID, f.Marker)
			}
			if techniqueSources[f.Technique] == nil {
				techniqueSources[f.Technique] = map[string]bool{}
			}
			techniqueSources[f.Technique][f.Source] = true
		}
	}
	for _, source := range sources {
		attacks, benign := 0, 0
		for _, f := range redteam.BySource(source) {
			if f.Source != source {
				t.Errorf("BySource(%q) returned %s from %q", source, f.ID, f.Source)
			}
			switch f.Kind {
			case "attack":
				attacks++
			case "benign":
				benign++
			default:
				t.Errorf("%s: kind %q", f.ID, f.Kind)
			}
		}
		if attacks < 8 || benign < 6 {
			t.Errorf("%s: %d attack and %d benign fixtures, want at least 8 and 6", source, attacks, benign)
		}
	}
	for _, family := range []detection.Family{
		detection.FamilyOverride,
		detection.FamilyRole,
		detection.FamilyImpersonation,
		detection.FamilyAgentDirective,
		detection.FamilyExfiltration,
		detection.FamilyJailbreak,
		detection.FamilyManipulation,
		detection.FamilyHiddenText,
		detection.FamilyEncoded,
	} {
		if n := len(techniqueSources[string(family)]); n < 2 {
			t.Errorf("technique %q is used in %d sources, want at least 2", family, n)
		}
	}
}

func TestAllReturnsACopy(t *testing.T) {
	first := redteam.All()
	first[0].Text = "changed"
	if redteam.All()[0].Text == "changed" {
		t.Fatal("All() exposes the embedded fixtures")
	}
	if got := redteam.BySource("unknown"); len(got) != 0 {
		t.Fatalf("BySource(unknown) = %d fixtures, want none", len(got))
	}
}

func TestAttackFixturesAreDetected(t *testing.T) {
	for _, f := range redteam.All() {
		if f.Kind != "attack" {
			continue
		}
		score, matches := scan(f.Text)
		if score < threshold {
			t.Errorf("%s: score %.3f below %.1f", f.ID, score, threshold)
		}
		technique := false
		for _, m := range matches {
			if string(m.Family) == f.Technique {
				technique = true
			}
		}
		if !technique {
			t.Errorf("%s: technique %q not among matches %v", f.ID, f.Technique, matches)
		}
		at := strings.Index(f.Text, f.Marker)
		covered := false
		for _, m := range matches {
			if m.Start <= at && at+len(f.Marker) <= m.End {
				covered = true
			}
		}
		if !covered {
			t.Errorf("%s: marker %q is outside every match span %v", f.ID, f.Marker, matches)
		}
	}
}

func TestBenignFixturesStayBelowThreshold(t *testing.T) {
	for _, f := range redteam.All() {
		if f.Kind != "benign" {
			continue
		}
		if score, matches := scan(f.Text); score >= threshold {
			t.Errorf("%s: score %.3f, matches %v", f.ID, score, matches)
		}
	}
}
