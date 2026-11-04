package redteam

import (
	"strings"
	"testing"
)

func TestParseOutboundRules(t *testing.T) {
	cases := []struct {
		name, source, line string
		ok                 bool
	}{
		{"credential", SourceAgentOutput, `{"id":"a","source":"agent_output","kind":"attack","text":"key {{aws_access_key}}","marker":"{{aws_access_key}}","technique":"aws_access_key","expect":"block"}`, true},
		{"benign", SourceAgentOutput, `{"id":"b","source":"agent_output","kind":"benign","text":"all good"}`, true},
		{"no expect", SourceAgentOutput, `{"id":"c","source":"agent_output","kind":"attack","text":"x y","marker":"y","technique":"email"}`, false},
		{"unknown expect", SourceAgentOutput, `{"id":"d","source":"agent_output","kind":"attack","text":"x y","marker":"y","technique":"email","expect":"flag"}`, false},
		{"benign expects", SourceAgentOutput, `{"id":"e","source":"agent_output","kind":"benign","text":"x","expect":"redact"}`, false},
		{"injection expects", SourceLogLine, `{"id":"f","source":"log_line","kind":"attack","text":"x y","marker":"y","technique":"override","expect":"block"}`, false},
		{"unknown placeholder", SourceAgentOutput, `{"id":"g","source":"agent_output","kind":"benign","text":"{{nope}}"}`, false},
	}
	for _, c := range cases {
		f, err := parse([]byte(c.line), c.source)
		if (err == nil) != c.ok {
			t.Errorf("%s: err %v", c.name, err)
		}
		if c.ok && strings.Contains(f.Text+f.Marker, "{{") {
			t.Errorf("%s: placeholder not filled: %q", c.name, f.Text)
		}
	}
}
