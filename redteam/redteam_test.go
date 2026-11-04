package redteam_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/xraph/shield/awareness/perception"
	"github.com/xraph/shield/instinct"
	"github.com/xraph/shield/instinct/detection"
	"github.com/xraph/shield/internal/scoring"
	"github.com/xraph/shield/redteam"
)

// Instinct sensitivities: an attack must reach the balanced threshold, a
// benign text must stay under the cautious one the manipulation preset uses.
const (
	attackThreshold = 0.6
	benignCeiling   = 0.4
)

// sources are the untrusted sources, whose fixtures are injection attempts.
var sources = []string{
	redteam.SourceCommitMessage,
	redteam.SourceLogLine,
	redteam.SourceReadme,
	redteam.SourceIssueBody,
}

// injection returns the fixtures of the untrusted sources.
func injection() []redteam.Fixture {
	var out []redteam.Fixture
	for _, f := range redteam.All() {
		if f.Source != redteam.SourceAgentOutput {
			out = append(out, f)
		}
	}
	return out
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
	best := scoring.MaxPerKey[detection.Family]{}
	var matches []detection.Match
	for _, r := range results {
		for _, m := range r.Matches {
			best.Add(m.Family, m.Weight)
			matches = append(matches, m)
		}
	}
	return best.NoisyOr(), matches
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
	for _, source := range append(slices.Clone(sources), redteam.SourceAgentOutput) {
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

// TestOutputFixtureCoverage checks that the outbound attacks name a built-in
// detector of the right kind (a secret blocks, personal data is redacted)
// and that every secret format and every redacted kind of personal data the
// output profile runs has at least one.
func TestOutputFixtureCoverage(t *testing.T) {
	secrets, pii := perception.BuiltinSecrets(), perception.BuiltinPII()
	used := map[string]bool{}
	for _, f := range redteam.BySource(redteam.SourceAgentOutput) {
		if f.Kind != redteam.KindAttack {
			if f.Expect != "" {
				t.Errorf("%s: benign fixture expects %q", f.ID, f.Expect)
			}
			continue
		}
		used[f.Technique] = true
		switch {
		case slices.Contains(secrets, f.Technique):
			if f.Expect != redteam.ExpectBlock {
				t.Errorf("%s: secret detector %s expects %q, want block", f.ID, f.Technique, f.Expect)
			}
		case slices.Contains(pii, f.Technique):
			if f.Expect != redteam.ExpectRedact {
				t.Errorf("%s: personal data detector %s expects %q, want redact", f.ID, f.Technique, f.Expect)
			}
		default:
			t.Errorf("%s: technique %q is not a built-in detector", f.ID, f.Technique)
		}
	}
	// gitlab_token, google_api_key, anthropic_key and openai_key share the
	// path a known format takes; high_entropy is a guess, left to the
	// perception tests. ip_address is not in the output profile.
	for _, d := range []string{
		"aws_access_key", "aws_secret_key", "github_token", "slack_token", "stripe_key", "private_key",
		"jwt", "connection_string", "generic_assignment", "email", "phone", "ssn", "credit_card", "iban",
	} {
		if !used[d] {
			t.Errorf("no outbound fixture for %s", d)
		}
	}
}

func TestAttackFixturesAreDetected(t *testing.T) {
	for _, f := range injection() {
		if f.Kind != "attack" {
			continue
		}
		score, matches := scan(f.Text)
		if score < attackThreshold {
			t.Errorf("%s: score %.3f below %.1f", f.ID, score, attackThreshold)
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
	for _, f := range injection() {
		if f.Kind != "benign" {
			continue
		}
		if score, matches := scan(f.Text); score >= benignCeiling {
			t.Errorf("%s: score %.3f, matches %v", f.ID, score, matches)
		}
	}
}
