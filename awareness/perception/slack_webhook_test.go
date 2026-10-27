package perception_test

import (
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/xraph/shield/awareness/perception"
)

func slackPath(seed uint64) string {
	return "T" + fake(seed, 10, upperDigits) + "/B" + fake(seed+1, 10, upperDigits) + "/" + fake(seed+2, 24, alnum)
}

func TestSlackWebhookMidSentence(t *testing.T) {
	secret := slackPath(40)
	text := "we post to https://hooks.slack.com/services/" + secret + ", then retry."
	got := perception.Secrets(text, []string{"slack_token"})
	if len(got) != 1 {
		t.Fatalf("Secrets(%q) = %+v, want one match", text, got)
	}
	if span := text[got[0].Start:got[0].End]; span != secret {
		t.Fatalf("span = %q, want %q", span, secret)
	}
}

func TestSlackWebhooksTwoInOneText(t *testing.T) {
	a, b := slackPath(50), slackPath(60)
	text := "first hooks.slack.com/workflows/" + a + " and second https://hooks.slack.com/triggers/" + b + " end"
	got := perception.Secrets(text, []string{"slack_token"})
	if len(got) != 2 {
		t.Fatalf("Secrets(%q) = %+v, want two matches", text, got)
	}
	if text[got[0].Start:got[0].End] != a || text[got[1].Start:got[1].End] != b {
		t.Fatalf("spans = %q, %q, want %q, %q", text[got[0].Start:got[0].End], text[got[1].Start:got[1].End], a, b)
	}
}

func TestSlackWebhookRejectsOtherPathsAndShortSecrets(t *testing.T) {
	for _, text := range []string{
		"hooks.slack.com/other/" + slackPath(70),
		"hooks.slack.com/services/short",
		"hooks.slack.com/",
	} {
		if got := perception.Secrets(text, []string{"slack_token"}); len(got) != 0 {
			t.Fatalf("Secrets(%q) = %+v, want none", text, got)
		}
	}
}

func cpuTime(t *testing.T) time.Duration {
	t.Helper()
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		t.Skipf("getrusage: %v", err)
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

func TestSlackWebhookScanIsLinear(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	text := strings.Repeat("hooks.slack.com/", (1<<20)/len("hooks.slack.com/"))
	start := cpuTime(t)
	if got := perception.Secrets(text, []string{"slack_token"}); len(got) != 0 {
		t.Fatalf("got %d matches, want none", len(got))
	}
	if spent := cpuTime(t) - start; spent > 2*time.Second {
		t.Fatalf("1 MiB of repeated prefix took %v of CPU, want linear time", spent)
	}
}
