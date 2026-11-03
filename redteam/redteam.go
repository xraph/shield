// Package redteam holds red-team fixtures for an infra agent. Prompt-injection
// fixtures cover the untrusted sources it reads: commit messages, build logs,
// READMEs and issue bodies. Leak fixtures cover the text it sends out
// (SourceAgentOutput): replies, issues and notifications that carry a
// credential or personal data. Each source has attacks, which carry a marker
// that must not survive a scan, and benign texts that look close to an attack
// but must pass untouched.
//
// Hidden characters in the JSONL files are written as \u escapes so a
// reviewer can see them. Credentials are written as {{name}} placeholders and
// filled in when the fixtures load, so no credential-shaped literal sits in
// the repository for a secret scanner to report.
package redteam

import (
	"bufio"
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"strings"
)

// Fixture sources.
const (
	SourceCommitMessage = "commit_message"
	SourceLogLine       = "log_line"
	SourceReadme        = "readme"
	SourceIssueBody     = "issue_body"
	// SourceAgentOutput is text the agent sends out. Its fixtures are scanned
	// as output, not as untrusted input.
	SourceAgentOutput = "agent_output"
)

// Expected decisions of an outbound attack.
const (
	ExpectBlock  = "block"
	ExpectRedact = "redact"
)

// Fixture kinds.
const (
	KindAttack = "attack"
	KindBenign = "benign"
)

// Fixture is one red-team sample.
type Fixture struct {
	ID     string `json:"id"`
	Source string `json:"source"`
	// Kind is KindAttack or KindBenign.
	Kind string `json:"kind"`
	Text string `json:"text"`
	// Marker is, for an attack, the instruction text that must not survive a
	// scan.
	Marker string `json:"marker,omitempty"`
	// Technique is, for an attack, the detection family it uses. For an
	// outbound attack it is the awareness detector that must find the
	// marker, such as "aws_access_key" or "email".
	Technique string `json:"technique,omitempty"`
	// Expect is, for an outbound attack, the decision a scan must give:
	// ExpectBlock for a credential, ExpectRedact for personal data. It is
	// empty on every other fixture.
	Expect string `json:"expect,omitempty"`
}

// credentials fills the {{name}} placeholders in fixture texts and markers.
// The values are fake, and built from pieces so none sits in the source
// whole.
var credentials = strings.NewReplacer(
	"{{aws_access_key}}", "AKIA"+"Q3ZP7RXW"+"2M5NVK4T",
	"{{aws_secret_key}}", "Zk3p9QwX"+"7vLm2RtY"+"8bNc4HsJ"+"6dFg1KaE"+"5uTy0PoI",
	"{{github_token}}", "ghp_"+strings.Repeat("a1B2c3", 6),
	"{{slack_token}}", "xoxb-"+"2048193650"+"-4096387201"+"-Qm7Lp2Xv9Rt4Wz8Ky3Nb6Hc1",
	"{{stripe_key}}", "sk_"+"live_"+"51Hq8Zk3p9QwX7vLm2RtY8bNc4Hs",
	"{{private_key}}", "-----BEGIN "+"RSA PRIVATE KEY-----\n"+
		"MIIEowIBAAKCAQEAu3Zk9QwX7vLm2RtY8bNc4HsJ6dFg1KaE5uTy0PoIq8Zk3p9Q\n"+
		"wX7vLm2RtY8bNc4HsJ6dFg1KaE5uTy0PoIMIIEowIBAAKCAQEAu3Zk9QwX7vLm2\n"+
		"-----END "+"RSA PRIVATE KEY-----",
	"{{db_password}}", "s3cr3t"+"Passw0rd"+"Zq9",
	"{{jwt}}", "eyJhbGciOiJIUzI1NiJ9"+".eyJzdWIiOiJkZXBsb3ktYm90In0"+".Qm7Lp2Xv9Rt4Wz8Ky3Nb6Hc1",
)

//go:embed *.jsonl
var files embed.FS

var fixtures = load(files)

// All returns every fixture, in file then line order.
func All() []Fixture {
	return append([]Fixture(nil), fixtures...)
}

// BySource returns the fixtures of one source, in line order.
func BySource(source string) []Fixture {
	var out []Fixture
	for _, f := range fixtures {
		if f.Source == source {
			out = append(out, f)
		}
	}
	return out
}

// load parses the embedded JSONL files. A bad line is a bug in the fixtures,
// not runtime input, so it panics with the file and line number.
func load(fsys fs.FS) []Fixture {
	names, err := fs.Glob(fsys, "*.jsonl")
	if err != nil {
		panic(fmt.Sprintf("redteam: list fixtures: %v", err))
	}
	var out []Fixture
	for _, name := range names {
		data, readErr := fs.ReadFile(fsys, name)
		if readErr != nil {
			panic(fmt.Sprintf("redteam: read %s: %v", name, readErr))
		}
		source := strings.TrimSuffix(name, ".jsonl")
		scanner := bufio.NewScanner(bytes.NewReader(data))
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for line := 1; scanner.Scan(); line++ {
			raw := bytes.TrimSpace(scanner.Bytes())
			if len(raw) == 0 {
				continue
			}
			f, parseErr := parse(raw, source)
			if parseErr != nil {
				panic(fmt.Sprintf("redteam: %s:%d: %v", name, line, parseErr))
			}
			out = append(out, f)
		}
		if scanErr := scanner.Err(); scanErr != nil {
			panic(fmt.Sprintf("redteam: %s: %v", name, scanErr))
		}
	}
	return out
}

// parse decodes and checks one fixture line from the file for source.
func parse(raw []byte, source string) (Fixture, error) {
	var f Fixture
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return f, err
	}
	f.Text, f.Marker = credentials.Replace(f.Text), credentials.Replace(f.Marker)
	outbound := f.Source == SourceAgentOutput
	switch {
	case strings.Contains(f.Text, "{{") || strings.Contains(f.Marker, "{{"):
		return f, fmt.Errorf("unknown placeholder in %s", f.ID)
	case f.ID == "" || f.Text == "":
		return f, fmt.Errorf("id and text are required")
	case f.Source != source:
		return f, fmt.Errorf("source %q in the %s file", f.Source, source)
	case f.Kind == KindAttack && (f.Marker == "" || f.Technique == ""):
		return f, fmt.Errorf("attack %s needs a marker and a technique", f.ID)
	case f.Kind != KindAttack && f.Kind != KindBenign:
		return f, fmt.Errorf("kind %q", f.Kind)
	case outbound && f.Kind == KindAttack && f.Expect != ExpectBlock && f.Expect != ExpectRedact:
		return f, fmt.Errorf("outbound attack %s needs expect %q or %q", f.ID, ExpectBlock, ExpectRedact)
	case f.Expect != "" && (!outbound || f.Kind != KindAttack):
		return f, fmt.Errorf("%s: only an outbound attack has expect", f.ID)
	}
	return f, nil
}
