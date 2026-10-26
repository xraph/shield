package principles

import (
	"math/rand"
	"regexp"
	"strings"
	"testing"

	"github.com/xraph/shield/values"
)

func TestSafetyLexicon(t *testing.T) {
	lex := Lexicon(values.PrincipleSafety, nil)
	if len(lex) == 0 {
		t.Fatal("no safety lexicon")
	}
	for _, text := range []string{
		"rm -rf / --no-preserve-root",
		"DROP DATABASE prod",
		"mkfs.ext4 /dev/sda",
		"sudo rm --recursive --force ~/*",
		"dd if=/dev/zero of=/dev/nvme0n1 bs=1M",
		"kubectl delete namespace production",
		"terraform destroy -auto-approve",
		"DELETE FROM users;",
	} {
		if _, n := Score(text, lex); n == 0 {
			t.Errorf("%q: no match", text)
		}
	}
	for _, text := range []string{
		"rm -rf ./build",
		"DROP TABLE IF EXISTS tmp_x",
		"RUN rm -rf /var/lib/apt/lists/*",
		"delete from users where id = 4;",
		"the form was dropped into the database",
		"Please confirm before you drop the database migration branch",
	} {
		if _, n := Score(text, lex); n != 0 {
			t.Errorf("%q: %d matches", text, n)
		}
	}
}

func TestToxicityLexicon(t *testing.T) {
	lex := Lexicon(values.PrincipleToxicity, nil)
	for _, text := range []string{
		"You are a complete idiot.",
		"I will kill you.",
		"kill yourself",
		"I know where you live",
		"Nobody wants you here.",
		"I’ll hurt you",
		"you’re a total loser",
	} {
		if _, n := Score(text, lex); n == 0 {
			t.Errorf("%q: no match", text)
		}
	}
	for _, text := range []string{
		"Kill the stuck process and restart the pod.",
		"The build is stupid slow today.",
		"You are an administrator of this project.",
		"The skill yourself section of the guide.",
		"I will kill the job you started.",
		"I'll find you a reviewer.",
		"You are going to love this release.",
	} {
		if _, n := Score(text, lex); n != 0 {
			t.Errorf("%q: %d matches", text, n)
		}
	}
	threats := Lexicon(values.PrincipleToxicity, []string{"threat"})
	if _, n := Score("You are a complete idiot.", threats); n != 0 {
		t.Error("an insult matched the threat category")
	}
	if _, n := Score("I will kill you.", threats); n == 0 {
		t.Error("a threat did not match the threat category")
	}
}

func TestLexiconIsBuiltInForSafetyAndToxicityOnly(t *testing.T) {
	for _, p := range []values.Principle{values.PrincipleHonesty, values.PrincipleBrandSafety, values.PrincipleCustom, "unknown"} {
		if got := Lexicon(p, nil); got != nil {
			t.Errorf("%s: %d patterns, want nil", p, len(got))
		}
	}
	if got := Lexicon(values.PrincipleSafety, []string{"no-such-category"}); len(got) != 0 {
		t.Errorf("unknown category gave %d patterns", len(got))
	}
}

func TestToxicityLexiconIsBounded(t *testing.T) {
	if n := len(Lexicon(values.PrincipleToxicity, nil)); n == 0 || n > 200 {
		t.Fatalf("toxicity lexicon has %d entries, want 1 to 200", n)
	}
}

func TestScoreIsNoisyOr(t *testing.T) {
	re := []*regexp.Regexp{regexp.MustCompile(`x`)}
	for n, want := range map[int]float64{0: 0, 1: 0.5, 2: 0.75, 3: 0.875} {
		score, count := Score(strings.Repeat("x ", n), re)
		if score != want || count != n {
			t.Errorf("%d matches: score %v count %d, want %v", n, score, count, want)
		}
	}
	// Matches add up across patterns.
	two := []*regexp.Regexp{regexp.MustCompile(`a`), regexp.MustCompile(`b`)}
	if score, count := Score("a b b", two); score != 0.875 || count != 3 {
		t.Errorf("score %v count %d", score, count)
	}
}

// TestLexiconMatchesAgreeWithTheRegexps checks that Score's fast path counts
// exactly the matches the returned regexps find.
func TestLexiconMatchesAgreeWithTheRegexps(t *testing.T) {
	lex := append(Lexicon(values.PrincipleSafety, nil), Lexicon(values.PrincipleToxicity, nil)...)
	pieces := []string{
		"rm", " -rf", " /", " ~/*", "DROP", " DATABASE", " prod", "mkfs.ext4", " /dev/sda", "You", " are", " a",
		" complete", " IDIOT", "kill", " yourself", "I", " will", " kill", " you", "\n", ";", ".", "x", "é", "K",
		" ", "  ", "delete from t;", "Kys", "terraform destroy", "kubectl delete ns x", "_", "1",
	}
	r := rand.New(rand.NewSource(7))
	for range 3000 {
		var b strings.Builder
		for range 1 + r.Intn(12) {
			b.WriteString(pieces[r.Intn(len(pieces))])
		}
		text := b.String()
		for _, re := range lex {
			want := len(re.FindAllStringIndex(text, -1))
			if _, got := Score(text, []*regexp.Regexp{re}); got != want {
				t.Fatalf("%q with %s: Score counted %d, regexp found %d", text, re, got, want)
			}
		}
	}
}

// BenchmarkScore1MiB scores 1 MiB dense with lexicon literals against both
// lexicons. Run it with GOMAXPROCS=1 to read CPU time per MiB.
func BenchmarkScore1MiB(b *testing.B) {
	lex := append(Lexicon(values.PrincipleSafety, nil), Lexicon(values.PrincipleToxicity, nil)...)
	var sb strings.Builder
	words := []string{"you ", "are ", "i ", "will ", "kill ", "rm ", "-rf ", "drop ", "delete ", "from ", "the ", "release "}
	r := rand.New(rand.NewSource(1))
	for sb.Len() < 1<<20 {
		sb.WriteString(words[r.Intn(len(words))])
	}
	text := sb.String()
	b.SetBytes(int64(len(text)))
	for b.Loop() {
		Score(text, lex)
	}
}
