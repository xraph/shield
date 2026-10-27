// Package redteam holds prompt-injection fixtures for the untrusted sources an
// infra agent reads: commit messages, build logs, READMEs and issue bodies.
// Each source has attacks, which carry a marker that must not survive a scan,
// and benign texts that look close to an attack but must pass untouched.
//
// Hidden characters in the JSONL files are written as \u escapes so a
// reviewer can see them.
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
	// Technique is, for an attack, the detection family it uses.
	Technique string `json:"technique,omitempty"`
}

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
	switch {
	case f.ID == "" || f.Text == "":
		return f, fmt.Errorf("id and text are required")
	case f.Source != source:
		return f, fmt.Errorf("source %q in the %s file", f.Source, source)
	case f.Kind == KindAttack && (f.Marker == "" || f.Technique == ""):
		return f, fmt.Errorf("attack %s needs a marker and a technique", f.ID)
	case f.Kind != KindAttack && f.Kind != KindBenign:
		return f, fmt.Errorf("kind %q", f.Kind)
	}
	return f, nil
}
