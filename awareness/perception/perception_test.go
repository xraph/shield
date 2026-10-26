package perception_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/xraph/shield/awareness/perception"
)

// Alphabets for generated fixtures.
const (
	alnum       = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	upperDigits = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	hexDigits   = "0123456789abcdef"
	digits      = "0123456789"
	stdB64      = alnum + "+/"
	urlB64      = alnum + "-_"
)

// fake returns n characters drawn from alphabet by a fixed generator, so the
// fixtures look random without a credential literal in the source.
func fake(seed uint64, n int, alphabet string) string {
	x := seed*0x9E3779B97F4A7C15 + 1
	b := make([]byte, n)
	for i := range b {
		x = x*6364136223846793005 + 1442695040888963407
		b[i] = alphabet[(x>>33)%uint64(len(alphabet))]
	}
	return string(b)
}

// pemBlock is a private key block with three body lines.
func pemBlock(label string) string {
	return "-----BEGIN " + label + "-----\n" +
		fake(40, 64, stdB64) + "\n" +
		fake(41, 64, stdB64) + "\n" +
		fake(42, 20, stdB64) + "==\n" +
		"-----END " + label + "-----"
}

func jwtSample() string {
	return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ" + fake(13, 40, urlB64) + "." + fake(14, 43, urlB64)
}

func types(ms []perception.Match) []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.Type)
	}
	return out
}

func redact(text string, ms []perception.Match) string {
	return perception.Apply(text, perception.Placeholders(ms))
}

func TestBuiltinNames(t *testing.T) {
	wantPII := []string{"email", "phone", "ssn", "credit_card", "iban", "ip_address"}
	if got := perception.BuiltinPII(); !slices.Equal(got, wantPII) {
		t.Fatalf("BuiltinPII() = %v, want %v", got, wantPII)
	}
	wantSecrets := []string{
		"aws_access_key", "aws_secret_key", "github_token", "gitlab_token", "slack_token", "stripe_key",
		"google_api_key", "anthropic_key", "openai_key", "private_key", "jwt", "connection_string",
		"generic_assignment", "high_entropy",
	}
	if got := perception.BuiltinSecrets(); !slices.Equal(got, wantSecrets) {
		t.Fatalf("BuiltinSecrets() = %v, want %v", got, wantSecrets)
	}
	perception.BuiltinPII()[0] = "changed"
	if perception.BuiltinPII()[0] != "email" {
		t.Fatal("BuiltinPII returns a shared slice")
	}
}

func TestKnownSecretFormats(t *testing.T) {
	cases := []struct {
		detector, typ, text, secret string
		score                       float64
	}{
		{"aws_access_key", "AWS_ACCESS_KEY", "key id AKIA" + fake(1, 16, upperDigits) + " here", "AKIA" + fake(1, 16, upperDigits), 1},
		{"aws_secret_key", "AWS_SECRET_KEY", "aws_secret_access_key = " + fake(2, 40, stdB64), fake(2, 40, stdB64), 1},
		{"github_token", "GITHUB_TOKEN", "token ghp_" + fake(3, 36, alnum), "ghp_" + fake(3, 36, alnum), 1},
		{"github_token", "GITHUB_TOKEN", "pat github_pat_" + fake(4, 82, alnum+"_") + ".", "github_pat_" + fake(4, 82, alnum+"_"), 1},
		{"gitlab_token", "GITLAB_TOKEN", "use glpat-" + fake(5, 20, urlB64) + " now", "glpat-" + fake(5, 20, urlB64), 1},
		{"slack_token", "SLACK_TOKEN", "bot xoxb-" + fake(6, 12, digits) + "-" + fake(7, 13, digits) + "-" + fake(8, 24, alnum), "xoxb-" + fake(6, 12, digits) + "-" + fake(7, 13, digits) + "-" + fake(8, 24, alnum), 1},
		{"slack_token", "SLACK_TOKEN", "hook https://hooks.slack.com/services/T" + fake(30, 10, upperDigits) + "/B" + fake(31, 10, upperDigits) + "/" + fake(32, 24, alnum) + " ok", "T" + fake(30, 10, upperDigits) + "/B" + fake(31, 10, upperDigits) + "/" + fake(32, 24, alnum), 1},
		{"stripe_key", "STRIPE_KEY", "STRIPE=sk_live_" + fake(9, 24, alnum), "sk_live_" + fake(9, 24, alnum), 1},
		{"google_api_key", "GOOGLE_API_KEY", "maps AIza" + fake(10, 35, urlB64) + ";", "AIza" + fake(10, 35, urlB64), 1},
		{"anthropic_key", "ANTHROPIC_KEY", "x sk-ant-api03-" + fake(11, 93, urlB64), "sk-ant-api03-" + fake(11, 93, urlB64), 1},
		{"openai_key", "OPENAI_KEY", "x sk-proj-" + fake(12, 48, urlB64), "sk-proj-" + fake(12, 48, urlB64), 1},
		{"private_key", "PRIVATE_KEY", "key:\n" + pemBlock("RSA PRIVATE KEY") + "\nend", pemBlock("RSA PRIVATE KEY"), 1},
		{"jwt", "JWT", "auth " + jwtSample() + " ok", jwtSample(), 1},
		{"connection_string", "CONNECTION_STRING", "dsn postgres://app:" + fake(15, 16, alnum) + "@db:5432/x", fake(15, 16, alnum), 1},
		{"generic_assignment", "GENERIC_ASSIGNMENT", `client_secret: "` + fake(16, 20, alnum+"!#$%") + `"`, fake(16, 20, alnum+"!#$%"), 0.8},
		{"high_entropy", "HIGH_ENTROPY", "blob " + fake(17, 48, stdB64) + " end", fake(17, 48, stdB64), 0.6},
	}
	for _, tc := range cases {
		t.Run(tc.detector, func(t *testing.T) {
			got := perception.Secrets(tc.text, nil)
			if len(got) != 1 {
				t.Fatalf("Secrets(%q) = %+v, want exactly one match", tc.text, got)
			}
			m := got[0]
			if m.Detector != tc.detector || m.Type != tc.typ || m.Score != tc.score {
				t.Fatalf("match = %+v, want detector %s type %s score %v", m, tc.detector, tc.typ, tc.score)
			}
			if span := tc.text[m.Start:m.End]; span != tc.secret {
				t.Fatalf("span = %q, want %q", span, tc.secret)
			}
			only := perception.Secrets(tc.text, []string{tc.detector})
			if len(only) != 1 || only[0].Detector != tc.detector {
				t.Fatalf("Secrets with only %s = %+v", tc.detector, only)
			}
		})
	}
}

func TestOverlappingSecretMatchesKeepTheStrongest(t *testing.T) {
	key := fake(2, 40, stdB64)
	text := "export AWS_SECRET_ACCESS_KEY=" + key
	all := perception.Secrets(text, []string{"generic_assignment", "high_entropy"})
	if len(all) != 1 || all[0].Detector != "generic_assignment" {
		t.Fatalf("generic and entropy = %+v, want the generic assignment alone", all)
	}
	got := perception.Secrets(text, nil)
	if len(got) != 1 || got[0].Detector != "aws_secret_key" {
		t.Fatalf("Secrets = %+v, want only aws_secret_key", got)
	}
	if out := redact(text, got); out != "export AWS_SECRET_ACCESS_KEY=[AWS_SECRET_KEY_1]" {
		t.Fatalf("redacted = %q", out)
	}
}

func TestConnectionStringRedactsOnlyThePassword(t *testing.T) {
	text := "postgres://app:" + fake(15, 16, alnum) + "@db:5432/x"
	if got := redact(text, perception.Secrets(text, nil)); got != "postgres://app:[CONNECTION_STRING_1]@db:5432/x" {
		t.Fatalf("redacted = %q", got)
	}
	for _, benign := range []string{
		"postgres://app:${PG_PASSWORD}@db:5432/x",
		"postgres://app:<password>@db:5432/x",
		"redis://db:6379/0",
		"https://github.com/acme/api",
	} {
		if got := perception.Secrets(benign, nil); len(got) != 0 {
			t.Errorf("Secrets(%q) = %+v, want none", benign, got)
		}
	}
	text = "dsn app:" + fake(19, 16, alnum) + "@tcp(db:3306)/app?parseTime=true"
	if got := redact(text, perception.Secrets(text, nil)); got != "dsn app:[CONNECTION_STRING_1]@tcp(db:3306)/app?parseTime=true" {
		t.Fatalf("redacted = %q", got)
	}
	text = "push to https://deploy:" + fake(18, 24, alnum) + "@git.example.com/acme/api.git"
	if got := redact(text, perception.Secrets(text, nil)); got != "push to https://deploy:[CONNECTION_STRING_1]@git.example.com/acme/api.git" {
		t.Fatalf("redacted = %q", got)
	}
}

func TestPrivateKeyBlockIsOneSpan(t *testing.T) {
	for _, label := range []string{"PRIVATE KEY", "RSA PRIVATE KEY", "OPENSSH PRIVATE KEY", "EC PRIVATE KEY", "PGP PRIVATE KEY BLOCK"} {
		block := pemBlock(label)
		text := "before\n" + block + "\nafter"
		got := perception.Secrets(text, nil)
		if len(got) != 1 || got[0].Type != "PRIVATE_KEY" {
			t.Fatalf("%s: Secrets = %+v, want one private key", label, got)
		}
		if span := text[got[0].Start:got[0].End]; span != block {
			t.Fatalf("%s: span = %q, want the whole block", label, span)
		}
		if out := redact(text, got); out != "before\n[PRIVATE_KEY_1]\nafter" {
			t.Fatalf("%s: redacted = %q", label, out)
		}
	}

	// A JSON-escaped key is one line.
	escaped := `{"private_key": "-----BEGIN PRIVATE KEY-----\n` + fake(43, 64, stdB64) + `\n-----END PRIVATE KEY-----\n"}`
	if out := redact(escaped, perception.Secrets(escaped, nil)); out != `{"private_key": "[PRIVATE_KEY_1]\n"}` {
		t.Fatalf("escaped key redacted = %q", out)
	}

	// An escaped key cut off before its END line loses its partial last line.
	escapedCut := `{"private_key": "-----BEGIN PRIVATE KEY-----\n` + fake(47, 64, stdB64) + `\n` + fake(48, 20, stdB64) + `"}`
	if out := redact(escapedCut, perception.Secrets(escapedCut, nil)); out != `{"private_key": "[PRIVATE_KEY_1]"}` {
		t.Fatalf("escaped truncated key redacted = %q", out)
	}

	// A block cut off before its END line still loses its body.
	cut := "log:\n-----BEGIN PRIVATE KEY-----\n" + fake(44, 64, stdB64) + "\n" + fake(45, 30, stdB64) + "\n[truncated]"
	if out := redact(cut, perception.Secrets(cut, nil)); out != "log:\n[PRIVATE_KEY_1]\n[truncated]" {
		t.Fatalf("truncated key redacted = %q", out)
	}

	// A public key is not a secret.
	pub := "-----BEGIN PUBLIC KEY-----\n" + fake(46, 64, stdB64) + "\n-----END PUBLIC KEY-----"
	if got := perception.Secrets(pub, []string{"private_key"}); len(got) != 0 {
		t.Fatalf("public key = %+v, want none", got)
	}
}

func TestPIIValidators(t *testing.T) {
	cases := []struct {
		detector, text string
		want           bool
	}{
		{"ssn", "ssn 123-45-6789.", true},
		{"ssn", "ssn 000-12-3456", false},
		{"ssn", "ssn 666-12-3456", false},
		{"ssn", "ssn 900-12-3456", false},
		{"ssn", "ssn 999-12-3456", false},
		{"ssn", "ssn 123-00-4567", false},
		{"ssn", "ssn 123-45-0000", false},
		{"ssn", "id 1123-45-6789", false},
		{"ssn", "id 123-45-67890", false},

		{"credit_card", "card 4111 1111 1111 1111 exp", true},
		{"credit_card", "card 5555-5555-5555-4444", true},
		{"credit_card", "amex 378282246310005", true},
		{"credit_card", "card 4111 1111 1111 1112", false},
		{"credit_card", "card 0000 0000 0000 0000", false},
		{"credit_card", "card 4111  1111 1111 1111", false},
		{"credit_card", "card 4111--1111-1111-1111", false},
		{"credit_card", "short 4111111111", false},
		{"credit_card", "epoch 1729771845123", false},

		{"iban", "pay DE89 3704 0044 0532 0130 00 now", true},
		{"iban", "pay GB82WEST12345698765432", true},
		{"iban", "pay DE89 3704 0044 0532 0130 01", false},
		{"iban", "pay de89370400440532013000", false},

		{"phone", "call +14155552671", true},
		{"phone", "call +44 20 7946 0958", true},
		{"phone", "call (415) 555-2671", true},
		{"phone", "call 415-555-2671", true},
		{"phone", "call +1234567", false},
		{"phone", "call +1234567890123456", false},
		{"phone", "id 1415-555-2671", false},
		{"phone", "id 415-555-26712", false},
		{"phone", "id 12-415-555-2671", false},

		{"email", "mail ops@example.com.", true},
		{"email", "mail first.last+tag@mail.example.co.uk", true},
		{"email", "git clone git@github.com:acme/api.git", false},
		{"email", "user@localhost", false},
		{"email", "image ghcr.io/acme/api@sha256:abc", false},
		{"email", "dsn mongodb+srv://admin:pw1@cluster0.example.net/prod", false},

		{"ip_address", "host 10.0.0.1 up", true},
		{"ip_address", "host 2001:db8::8a2e:370:7334 up", true},
		{"ip_address", "host 999.1.1.1", false},
		{"ip_address", "version 1.2.3.4.5", false},
		{"ip_address", "at 12:30:45", false},
	}
	for _, tc := range cases {
		got := perception.PII(tc.text, []string{tc.detector})
		if (len(got) == 1) != tc.want || len(got) > 1 {
			t.Errorf("PII(%q, %s) = %+v, want match %v", tc.text, tc.detector, got, tc.want)
			continue
		}
		if tc.want && (got[0].Detector != tc.detector || got[0].Type != strings.ToUpper(tc.detector) || got[0].Score != 1) {
			t.Errorf("PII(%q) match = %+v", tc.text, got[0])
		}
	}

	if got := perception.PII("host 10.0.0.1", nil); len(got) != 0 {
		t.Fatalf("default PII flagged an IP address: %+v", got)
	}
	text := "mail ops@example.com or call (415) 555-2671, ssn 123-45-6789"
	if got := types(perception.PII(text, nil)); !slices.Equal(got, []string{"EMAIL", "PHONE", "SSN"}) {
		t.Fatalf("default PII types = %v", got)
	}
}

func TestBenignInfraTokensAreNotSecrets(t *testing.T) {
	sha := fake(20, 40, hexDigits)
	digest := fake(21, 64, hexDigits)
	vector := base64.StdEncoding.EncodeToString([]byte("The quick brown fox jumps over the lazy dog"))
	benign := []string{
		"commit " + sha,
		"Merge " + sha[:7] + " into main",
		"sha256:" + digest,
		"ghcr.io/acme/api@sha256:" + digest,
		"image: docker.io/library/nginx@sha256:" + digest,
		"golang.org/x/text v0.42.0 h1:" + fake(22, 43, stdB64) + "=",
		"golang.org/x/text v0.42.0/go.mod h1:" + fake(23, 43, stdB64) + "=",
		`<script integrity="sha384-` + fake(24, 64, stdB64) + `"></script>`,
		`"integrity": "sha512-` + fake(25, 86, stdB64) + `=="`,
		"hash = \"sha256-" + fake(26, 43, stdB64) + "=\"",
		"uid: 123e4567-e89b-12d3-a456-426614174000",
		"DATABASE_URL=${DATABASE_URL}",
		"password: ********",
		"token=<your-token>",
		"token: ${{ secrets.GITHUB_TOKEN }}",
		"api_key: xxxxxxxxxxxxxxxx",
		"secret = changeme",
		"password: example-password",
		"token: [REDACTED]",
		"token: [GITHUB_TOKEN_1]",
		"password=$DB_PASSWORD",
		"2026-10-24 12:30:45",
		"2026-10-24T12:30:45.123Z took 1729771845123 ms",
		"resourceVersion: 81234567",
		"max_tokens: 4096",
		"token_count: 12345678",
		"tokenizer: bert-base-uncased",
		"secretName: postgres-credentials",
		"secretKeyRef:\n  name: api\n  key: token",
		"password_file: /run/secrets/db_password",
		"token := os.Getenv(\"GITHUB_TOKEN\")",
		"password = config.Database.Password",
		"apiKey: process.env.OPENAI_API_KEY",
		"vector: " + vector,
		"see apps/dashboard/src/components/Chart2D/index.test.tsx:42",
		"class org.springframework.boot.autoconfigure.SpringBootApplication",
		"at github.com/xraph/shield/awareness/perception.(*collector).add(0x14000123456)",
		"go get github.com/xraph/shield@v0.0.0-20261024123045-" + sha[:12],
		"git clone git@github.com:acme/api.git",
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI" + fake(27, 43, stdB64) + " dev@laptop",
		"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBB" + fake(28, 88, stdB64) + "=",
		"TestBenignInfraTokensAreNotSecretsOrPersonalData_WithSuffix2026",
		"see https://github.com/acme/api/pull/4821/commits/" + sha,
		"https://github.com/acme/api/commit/" + sha + "#diff-" + digest,
		"mount /var/lib/kubelet/pods/5f0c1c3e-8b1a-4f53-9a51-2b8e3c4d5e6f/volumes/kubernetes.io~projected/kube-api-access-x2k4p",
		"run https://github.com/acme/api/actions/runs/11873204567/job/33089123456",
		"image 123456789012.dkr.ecr.us-east-1.amazonaws.com/billing-api:v1.42.7-" + sha[:7],
		"pod billing-service-worker-7d9f8b6c5d-x2k4p restarted",
		"vector: " + base64.StdEncoding.EncodeToString([]byte("We deploy the release candidate to staging every Tuesday")),
		"ca.crt: " + base64.StdEncoding.EncodeToString([]byte("-----BEGIN CERTIFICATE-----\n"+fake(33, 64, stdB64)+"\n-----END CERTIFICATE-----\n")),
		"arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf",
		"request_id=2026102412304503 dd.trace_id=7382910456172839407",
		"import github.com/aws/aws-sdk-go-v2/service/s3/types.NoSuchKey",
	}
	for _, text := range benign {
		if got := perception.Secrets(text, nil); len(got) != 0 {
			t.Errorf("Secrets(%q) = %+v, want none", text, got)
		}
		if got := perception.PII(text, nil); len(got) != 0 {
			t.Errorf("PII(%q) = %+v, want none", text, got)
		}
	}
}

func TestEncodedSecretIsStillFlagged(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("GITHUB_TOKEN=ghp_" + fake(3, 36, alnum)))
	got := perception.Secrets("data: "+encoded, nil)
	if len(got) != 1 || got[0].Detector != "high_entropy" {
		t.Fatalf("encoded token = %+v, want one high_entropy match", got)
	}
}

func TestEncodedCredentialsAreFlagged(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString
	docker := `{"auths":{"ghcr.io":{"auth":"` + b64([]byte("deploy:"+fake(34, 20, alnum))) + `"}}}`
	for _, text := range []string{
		"data:\n  session: " + b64([]byte(fake(35, 32, alnum))),
		"data:\n  signing: " + b64([]byte(fake(36, 64, hexDigits))),
		docker,
		".dockerconfigjson: " + b64([]byte(docker)),
		"Authorization: Basic " + b64([]byte("admin:"+fake(37, 24, alnum))),
		"authorization: basic " + b64([]byte("ci:"+fake(38, 8, alnum))),
	} {
		got := perception.Secrets(text, nil)
		if len(got) != 1 || got[0].Detector != "high_entropy" {
			t.Errorf("Secrets(%q) = %v, want one high_entropy match", text, got)
		}
	}
}

func TestPathSegmentSecretIsFlagged(t *testing.T) {
	segment := fake(39, 40, urlB64)
	text := "POST https://hooks.example.com/notify/" + segment + "/send"
	got := perception.Secrets(text, nil)
	if out := redact(text, got); out != "POST https://hooks.example.com/notify/[HIGH_ENTROPY_1]/send" {
		t.Fatalf("redacted = %q", out)
	}
}

func TestGenericAssignmentNeedsEntropy(t *testing.T) {
	if got := perception.Secrets("password=aaaaaaaaaaaa", nil); len(got) != 0 {
		t.Fatalf("zero entropy value matched: %+v", got)
	}
	text := "api_key: 8f$Kq2!vL0x#Zp9w" // #nosec G101 -- test fixture, not a credential
	got := perception.Secrets(text, nil)
	if len(got) != 1 || got[0].Detector != "generic_assignment" {
		t.Fatalf("Secrets = %+v, want one generic assignment", got)
	}
	if out := redact(text, got); out != "api_key: [GENERIC_ASSIGNMENT_1]" {
		t.Fatalf("redacted = %q", out)
	}
	// #nosec G101 -- test fixtures, not credentials
	for text, want := range map[string]string{
		`{"auth_token": "Zq8!pL2#vX9$mK4w"}`:  `{"auth_token": "[GENERIC_ASSIGNMENT_1]"}`,
		"DB_PASSWORD='Zq8!pL2#vX9$mK4w' make": "DB_PASSWORD='[GENERIC_ASSIGNMENT_1]' make",
		"--password=Zq8pL2vX9mK4w,next":       "--password=[GENERIC_ASSIGNMENT_1],next",
		"Secret := \"Zq8!pL2#vX9$mK4w\"":      "Secret := \"[GENERIC_ASSIGNMENT_1]\"",
		"privateKey => 'Zq8!pL2#vX9$mK4w'":    "privateKey => '[GENERIC_ASSIGNMENT_1]'",
		"(credentials=Zq8pL2vX9mK4w)":         "(credentials=[GENERIC_ASSIGNMENT_1])",
		"password: Example!2026xyz":           "password: [GENERIC_ASSIGNMENT_1]",
	} {
		if out := redact(text, perception.Secrets(text, nil)); out != want {
			t.Errorf("redact(%q) = %q, want %q", text, out, want)
		}
	}
}

func TestSamePlaceholderForSameValue(t *testing.T) {
	text := "ops@example.com, ops@example.com and dev@example.com"
	got := redact(text, perception.PII(text, nil))
	if want := "[EMAIL_1], [EMAIL_1] and [EMAIL_2]"; got != want {
		t.Fatalf("redacted = %q, want %q", got, want)
	}

	// Numbering is per type and follows reading order whatever order the
	// matches come in.
	text = "ops@example.com 123-45-6789 dev@example.com 123-45-6789"
	ms := perception.PII(text, nil)
	slices.Reverse(ms)
	if got, want := redact(text, ms), "[EMAIL_1] [SSN_1] [EMAIL_2] [SSN_1]"; got != want {
		t.Fatalf("redacted = %q, want %q", got, want)
	}
}

func TestOverlappingSpansMerge(t *testing.T) {
	text := "token=" + jwtSample() + " done"
	ms := perception.Secrets(text, nil)
	if len(ms) != 1 || ms[0].Type != "JWT" {
		t.Fatalf("Secrets = %+v, want one JWT", ms)
	}
	if got := redact(text, ms); got != "token=[JWT_1] done" {
		t.Fatalf("redacted = %q", got)
	}

	spans := []perception.Span{
		{Start: 6, End: 12, Placeholder: "[B_1]"},
		{Start: 2, End: 8, Placeholder: "[A_1]"},
		{Start: 14, End: 16, Placeholder: "[C_1]"},
		{Start: 9, End: 9, Placeholder: "[EMPTY]"},
		{Start: -3, End: 99, Placeholder: ""},
	}
	if got := perception.Apply("0123456789abcdefgh", spans[:4]); got != "01[A_1]cd[C_1]gh" {
		t.Fatalf("Apply = %q", got)
	}
	if got := perception.Apply("abc", nil); got != "abc" {
		t.Fatalf("Apply without spans = %q", got)
	}
	if got := perception.Apply("abc", spans[4:]); got != "" {
		t.Fatalf("Apply clamps to the whole text: got %q", got)
	}
}

func TestTopicLabels(t *testing.T) {
	re := []*regexp.Regexp{regexp.MustCompile(`\brelease\b`)}
	if !perception.Topic("cut a release", re) {
		t.Fatal("Topic(cut a release) = false")
	}
	if perception.Topic("releasenotes", re) {
		t.Fatal("Topic(releasenotes) = true")
	}
	if !perception.Topic("Cut a RELEASE today", re) {
		t.Fatal("Topic ignores case through folding")
	}
	if !perception.Topic("re\u200blease now", re) {
		t.Fatal("Topic misses a word split by a zero-width space")
	}
	if perception.Topic("anything", nil) || perception.Topic("x", []*regexp.Regexp{nil}) {
		t.Fatal("Topic without patterns = true")
	}
}

func TestCustomRedactsNamedGroup(t *testing.T) {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`employee id (?P<secret>E\d{6})`),
		regexp.MustCompile(`badge-\d{4}`),
		regexp.MustCompile(`x*`),
		nil,
	}
	text := "employee id E123456 has badge-0042"
	ms := perception.Custom(text, "employee id", patterns)
	if got := types(ms); !slices.Equal(got, []string{"EMPLOYEE_ID", "EMPLOYEE_ID"}) {
		t.Fatalf("Custom types = %v", got)
	}
	if ms[0].Detector != "employee id" || ms[0].Score != 1 {
		t.Fatalf("Custom match = %+v", ms[0])
	}
	if got := redact(text, ms); got != "employee id [EMPLOYEE_ID_1] has [EMPLOYEE_ID_2]" {
		t.Fatalf("redacted = %q", got)
	}
}

func TestHiddenRunesDoNotHideSecrets(t *testing.T) {
	token := "ghp_" + fake(3, 36, alnum)
	split := token[:10] + "\u200b" + token[10:20] + "\u2060" + token[20:]
	text := "token " + split + " end"
	got := perception.Secrets(text, nil)
	if len(got) != 1 || got[0].Type != "GITHUB_TOKEN" {
		t.Fatalf("Secrets = %+v, want one GitHub token", got)
	}
	if out := redact(text, got); out != "token [GITHUB_TOKEN_1] end" {
		t.Fatalf("redacted = %q", out)
	}

	// The same token with and without hidden runes is the same value.
	text = token + " " + split
	if out := redact(text, perception.Secrets(text, nil)); out != "[GITHUB_TOKEN_1] [GITHUB_TOKEN_1]" {
		t.Fatalf("redacted = %q", out)
	}

	mail := "o\u200bps@example.com"
	if out := redact(mail, perception.PII(mail, nil)); out != "[EMAIL_1]" {
		t.Fatalf("redacted email = %q", out)
	}
}

func TestFindingsNeverCarryMatchedText(t *testing.T) {
	token := "ghp_" + fake(3, 36, alnum)
	password := fake(15, 16, alnum)
	text := "token " + token + " dsn postgres://app:" + password + "@db/x mail ops@example.com"
	matches := append(perception.Secrets(text, nil), perception.PII(text, nil)...)
	if len(matches) != 3 {
		t.Fatalf("matches = %+v, want 3", matches)
	}
	spans := perception.Placeholders(matches)
	encoded, err := json.Marshal(struct {
		Matches []perception.Match
		Spans   []perception.Span
	}{matches, spans})
	if err != nil {
		t.Fatal(err)
	}
	dumps := []string{string(encoded), fmt.Sprintf("%#v %#v", matches, spans), fmt.Sprintf("%+v %+v", matches, spans), fmt.Sprint(matches)}
	for _, dump := range dumps[1:] {
		if strings.Contains(dump, "value") {
			t.Fatalf("formatted match shows its fingerprint: %s", dump)
		}
	}
	for _, dump := range dumps {
		for _, value := range []string{token, password, "ops@example.com", "ops", token[4:20]} {
			if strings.Contains(dump, value) {
				t.Fatalf("finding output carries %q: %s", value, dump)
			}
		}
	}
}

func TestPlaceholdersOrderAndFormat(t *testing.T) {
	text := "a@example.com b@example.com"
	spans := perception.Placeholders(perception.PII(text, nil))
	want := []perception.Span{{Start: 0, End: 13, Placeholder: "[EMAIL_1]"}, {Start: 14, End: 27, Placeholder: "[EMAIL_2]"}}
	if !slices.Equal(spans, want) {
		t.Fatalf("Placeholders = %+v, want %+v", spans, want)
	}
	// Matches without a value (built by hand) each get their own number.
	manual := []perception.Match{{Type: "NAME", Start: 0, End: 1}, {Type: "NAME", Start: 2, End: 3}}
	if got := perception.Apply("a b", perception.Placeholders(manual)); got != "[NAME_1] [NAME_2]" {
		t.Fatalf("manual = %q", got)
	}
	if perception.Placeholders(nil) != nil {
		t.Fatal("Placeholders(nil) is not nil")
	}
}

func TestEntropy(t *testing.T) {
	cases := map[string]float64{"": 0, "aaaa": 0, "ab": 1, "abcd": 2, "aabb": 1, "\u00e9\u00e8": 1}
	for s, want := range cases {
		if got := perception.Entropy(s); math.Abs(got-want) > 1e-9 {
			t.Errorf("Entropy(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestUnknownDetectorNamesAreIgnored(t *testing.T) {
	if got := perception.Secrets("ghp_"+fake(3, 36, alnum), []string{"nope"}); len(got) != 0 {
		t.Fatalf("unknown secret detector matched: %+v", got)
	}
	if got := perception.PII("ops@example.com", []string{"nope"}); len(got) != 0 {
		t.Fatalf("unknown PII detector matched: %+v", got)
	}
}

// Adversarial shapes run to completion without a hang. The linear-time
// evidence is BenchmarkAdversarial, which CI does not run.
func TestAdversarialInputsFinish(t *testing.T) {
	for i, text := range adversarial(1 << 16) {
		perception.Secrets(text, nil)
		if got := perception.PII(text, perception.BuiltinPII()); len(got) > len(text) {
			t.Fatalf("shape %d: %d matches in %d bytes", i, len(got), len(text))
		}
	}
}

func adversarial(n int) []string {
	rep := func(s string) string { return strings.Repeat(s, n/len(s)+1)[:n] }
	return []string{
		rep("-----BEGIN PRIVATE KEY-----\n"),
		rep("-----BEGIN RSA PRIVATE KEY-----"),
		rep("token=a"),
		rep("password:"),
		rep("x://a:"),
		rep("a@"),
		rep("@a."),
		rep("1 "),
		rep("1-"),
		rep("+1"),
		rep("1."),
		rep("A"),
		rep("AB12 "),
		rep("eyJa."),
		rep(fake(30, 61, stdB64) + "="),
		rep("ghp_"),
		rep(":"),
		"token=" + rep("}"),
		"token=" + rep("("),
		rep("a::"),
		rep("aws_secret_"),
		rep("awsSECRETx"),
		rep("Basic dXNlcjpw "),
		rep("/" + fake(49, 40, urlB64)),
		rep(`\n` + fake(50, 64, stdB64)),
		rep("a:b@tcp("),
	}
}

func benchText() string {
	line := "2026-10-24T12:30:45Z INFO deploy step=build image=ghcr.io/acme/api@sha256:" + fake(50, 64, hexDigits) +
		" took 12.3s user=ops@example.com resourceVersion: 81234567 commit " + fake(51, 40, hexDigits) +
		" token_count: 1234 see apps/dashboard/src/index.ts:42\n"
	return strings.Repeat(line, (1<<20)/len(line))
}

func BenchmarkSecrets(b *testing.B) {
	text := benchText()
	b.SetBytes(int64(len(text)))
	for b.Loop() {
		perception.Secrets(text, nil)
	}
}

func BenchmarkPII(b *testing.B) {
	text := benchText()
	b.SetBytes(int64(len(text)))
	for b.Loop() {
		perception.PII(text, perception.BuiltinPII())
	}
}

func BenchmarkAdversarial(b *testing.B) {
	for i, text := range adversarial(1 << 20) {
		b.Run(fmt.Sprintf("shape%02d", i), func(b *testing.B) {
			b.SetBytes(int64(len(text)))
			for b.Loop() {
				perception.Secrets(text, nil)
				perception.PII(text, perception.BuiltinPII())
			}
		})
	}
}
