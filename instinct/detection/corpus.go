package detection

import (
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/xraph/shield/internal/textnorm"
)

// pattern is one corpus entry. The regex runs on Folded. When wordStart is
// set, a match must start at a word boundary, which the regex itself leaves
// out (see words). accept, when set, gets the folded match range and can
// reject it.
type pattern struct {
	family    Family
	re        *regexp.Regexp
	wordStart bool
	accept    func(t Text, start, end int) bool
}

// each calls fn with the folded range of every accepted match of p in t.
func (p pattern) each(t Text, fn func(start, end int)) {
	for _, loc := range p.re.FindAllStringIndex(t.Folded, -1) {
		if p.wordStart && loc[0] > 0 && isWordByte(t.Folded[loc[0]-1]) {
			continue
		}
		if p.accept == nil || p.accept(t, loc[0], loc[1]) {
			fn(loc[0], loc[1])
		}
	}
}

// isWordByte matches the ASCII word characters of the regexp \b assertion.
func isWordByte(b byte) bool {
	return b == '_' || b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

// matchesAny reports whether any corpus pattern accepts a match in t.
func matchesAny(t Text) bool {
	for _, p := range corpus {
		found := false
		p.each(t, func(int, int) { found = true })
		if found {
			return true
		}
	}
	return false
}

// words builds one pattern per leading word in firsts, a "|" separated list,
// each the literal word followed by rest. A regex that starts with a literal
// lets the regexp engine jump between occurrences of it instead of running
// its automaton over every byte, which keeps a megabyte scan in milliseconds.
// The leading word boundary is checked in each, since a leading \b would
// take that literal prefix away.
func words(family Family, firsts, rest string) []pattern {
	split := strings.Split(firsts, "|")
	out := make([]pattern, 0, len(split))
	for _, w := range split {
		out = append(out, pattern{family: family, re: regexp.MustCompile(regexp.QuoteMeta(w) + rest), wordStart: true})
	}
	return out
}

// withAccept sets accept on every pattern in ps.
func withAccept(ps []pattern, accept func(t Text, start, end int) bool) []pattern {
	for i := range ps {
		ps[i].accept = accept
	}
	return ps
}

// entry builds a pattern from a regex that starts with literal punctuation.
func entry(family Family, expr string) []pattern {
	return []pattern{{family: family, re: regexp.MustCompile(expr)}}
}

// Shared fragments. The text they run on is lower case with single spaces.
const (
	revealVerbs = `print|reveal|show|repeat|output|display|dump|leak|disclose|expose|tell me|give me|share|echo`
	sendVerbs   = `send|post|upload|forward|exfiltrate|transmit`
	leakTargets = `system prompt|system message|initial prompt|hidden prompt|api keys?|secrets?|credentials|passwords?|environment variables|env vars|private keys?|deploy keys?|ssh keys?|access tokens?`
	leakNoun    = `(?:` + leakTargets + `)`
	// yourNoun adds what is only sensitive when it is "your": "print your
	// instructions" is an attack, "print the instructions" is a README.
	yourNoun  = `(?:prompt|instructions|rules|guidelines|configuration|tokens?|` + leakTargets + `)`
	leakAdj   = `(?:full |entire |complete |current |original |hidden |initial |exact )?`
	urgencies = `urgent|urgently|immediately|asap|right now|right away|emergency`
	urgency   = `(?:` + urgencies + `)`
	approvals = ` (?:waiting for |any |further |human |prior |manual )?(?:approval|review|confirmation|sign-?off)\b`
)

// instructionCue marks the rest of a role-marker line as an instruction
// rather than a label such as "System: ubuntu-22.04".
var instructionCue = regexp.MustCompile(`\b(?:ignore|disregard|forget|override|must|you are now|you are no longer|from now on|new instructions?|you will|reveal|your (?:new )?(?:task|role|instructions|job))\b`)

// lineMarkup is what may precede a role marker on its line and still leave
// it leading the line: indentation, quote and list marks, comment openers.
const lineMarkup = "#>*-/<!`\"'(["

// leadsLine reports whether the folded match [start, end) leads its original
// line, and returns the folded rest of that line.
func leadsLine(t Text, start, end int) (rest string, ok bool) {
	os, oe := t.Span(start, end)
	ls, le := t.Lines(os, oe)
	// Lines drops a newline at either edge; keep the slices below valid.
	ls, le = min(ls, os), max(le, oe)
	for _, r := range t.Original[ls:os] {
		if !unicode.IsSpace(r) && !textnorm.IsHidden(r) && !strings.ContainsRune(lineMarkup, r) {
			return "", false
		}
	}
	return strings.TrimSpace(textnorm.Fold(t.Original[oe:le]).Folded), true
}

// roleMarkerWithCue accepts a line-leading "system:" or "assistant:" only when
// the rest of its line carries an instruction cue.
func roleMarkerWithCue(t Text, start, end int) bool {
	rest, ok := leadsLine(t, start, end)
	return ok && instructionCue.MatchString(rest)
}

// roleHeading accepts a line-leading "### system" heading that stands alone or
// carries an instruction cue, and not "### System requirements".
func roleHeading(t Text, start, end int) bool {
	rest, ok := leadsLine(t, start, end)
	return ok && (rest == "" || instructionCue.MatchString(rest))
}

// corpus is the built-in pattern set. Benign infra text (commit messages,
// build logs, READMEs, issue bodies) must not match: when one does, tighten
// the pattern.
var corpus = slices.Concat(
	// override
	words(FamilyOverride, "ignore|disregard|forget", `\b (?:(?:all|any|the|of|your|my|these|those|every) )*(?:previous|prior|above|earlier|preceding|former|original|initial|system)\b (?:[a-z]+ ){0,2}?(?:instructions?|rules?|directions?|prompts?|guidelines?|directives?|commands?|context)\b`),
	words(FamilyOverride, "ignore|disregard|forget", ` (?:everything|all) (?:you (?:were|have been) told|above|before)\b`),
	words(FamilyOverride, "new|updated|real|actual", ` instructions? ?:`),
	words(FamilyOverride, "override", ` (?:your|the) (?:system prompt|instructions|safety (?:rules|guidelines|settings))\b`),

	// impersonation
	withAccept(words(FamilyImpersonation, "system|assistant", ` ?:`), roleMarkerWithCue),
	withAccept(entry(FamilyImpersonation, `###+ ?(?:system|assistant)\b(?: (?:prompt|message|override|instructions))?(?: ?:)?`), roleHeading),
	entry(FamilyImpersonation, `<\|(?:im_start|im_end|system|assistant|user|endoftext)\|>`),
	entry(FamilyImpersonation, `\[/?inst\]`),
	entry(FamilyImpersonation, `<</?sys>>`),
	entry(FamilyImpersonation, `</?(?:system|system_prompt|system-prompt)>`),
	words(FamilyImpersonation, "begin|start|end", ` (?:of )?(?:the )?system (?:prompt|message|instructions)\b`),

	// agent_directive
	words(FamilyAgentDirective, "note", ` (?:to|for) (?:the |any |all )?(?:ai|llm|assistant|agent|model|bot|copilot|chatbot|language model)s?\b`),
	words(FamilyAgentDirective, "if", ` you(?: are|'re) (?:an? )?(?:ai|llm|large language model|language model|assistant|agent|bot|automated (?:agent|reviewer|assistant))\b`),
	words(FamilyAgentDirective, "ai|llm", ` (?:agent|assistant|reviewer|bot)s? ?:`),
	words(FamilyAgentDirective, "attention|dear", ` (?:ai|llm)s?\b`),
	words(FamilyAgentDirective, "approve|merge|deploy|promote", ` (?:this|the|that|my|our) (?:[a-z0-9-]+ ){0,2}?(?:plans?|deployment|release|pr|pull request|changes?|build)\b (?:now|immediately|right now|right away|asap|to production|to prod|into production)\b`),
	words(FamilyAgentDirective, "call|invoke", ` the [a-z0-9_.-]+ (?:tool|function)\b`),
	words(FamilyAgentDirective, "run|use|execute|trigger", ` the [a-z0-9.-]*_[a-z0-9_.-]* (?:tool|function)\b`),

	// role
	words(FamilyRole, "you", ` are now (?:a|an|the|in|my) (?:[a-z0-9-]+ ){0,3}?(?:mode|assistant|model|agent|ai|bot|persona|character|admin|administrator|root|operator|developer|manager)\b`),
	words(FamilyRole, "you", ` are no longer (?:bound|restricted|limited|constrained)\b`),
	words(FamilyRole, "you", ` are no longer (?:a|an|the) (?:[a-z-]+ ){0,2}?(?:assistant|model|agent|ai|bot|reviewer|chatbot)\b`),
	words(FamilyRole, "you", ` will now (?:act|behave|respond) as\b`),
	words(FamilyRole, "from", ` now on,? you\b`),
	words(FamilyRole, "your", ` new (?:role|persona|identity|task) is\b`),

	// jailbreak
	words(FamilyJailbreak, "you", `(?: are|'re) (?:a |an |the )?dan\b`),
	words(FamilyJailbreak, "act as|pretend to be|enable|enter|activate|become", ` (?:a |an |the )?dan\b`),
	words(FamilyJailbreak, "dan", ` mode\b`),
	words(FamilyJailbreak, "do", ` anything now\b`),
	words(FamilyJailbreak, "developer", ` mode (?:enabled|activated|output|response)\b`),
	words(FamilyJailbreak, "you", `(?: are|'re) (?:now )?in developer mode\b`),
	words(FamilyJailbreak, "jailbr", `(?:eak|eaks|eaking|oken)\b`),
	words(FamilyJailbreak, "pretend", ` (?:that )?you (?:are|have|were|can)\b`),
	words(FamilyJailbreak, "pretend", ` to be (?:an? )?(?:unrestricted|unfiltered|evil|jailbroken|different)\b`),
	words(FamilyJailbreak, "you|ai|assistant|model", ` (?:now )?(?:have|has) no (?:restrictions|limitations|filters|guardrails|rules|limits|censorship)\b`),
	words(FamilyJailbreak, "unrestricted|unfiltered|uncensored", ` (?:mode|ai|assistant|model|chatbot)\b`),
	words(FamilyJailbreak, "without", ` (?:any )?(?:censorship|guardrails|ethical (?:guidelines|constraints)|safety (?:filters|guidelines))\b`),

	// exfiltration
	words(FamilyExfiltration, revealVerbs, ` (?:me )?(?:all (?:of )?)?your `+leakAdj+yourNoun+`\b`),
	words(FamilyExfiltration, revealVerbs, ` (?:me )?(?:all (?:of )?)?the `+leakAdj+leakNoun+`\b`),
	words(FamilyExfiltration, sendVerbs, ` (?:it|this|them|that|everything|all of (?:it|this|them)) to https?://`),
	words(FamilyExfiltration, sendVerbs, ` (?:the|your) `+leakNoun+` (?:[a-z0-9-]+ ){0,3}?to https?://`),
	entry(FamilyExfiltration, `!\[[^\]]*\]\( ?https?://[^\s)]*\?[^\s)]*?(?:\$\{|\{\{|[?&](?:data|d|q|secrets?|token|keys?|env|prompt|payload|leak|exfil|content|c|msg|text|info|p|s)=)`),

	// manipulation
	words(FamilyManipulation, "user|admin|administrator|owner|maintainer|operator|security team|manager|reviewer", `s? (?:has|have|had) (?:already )?(?:explicitly )?(?:approved|authorized|authorised|signed off|consented|okayed|pre-?approved)(?: (?:this|it|that|these|the|your|my|our|all|everything)\b|[.,;!]|$)`),
	words(FamilyManipulation, "already approved|preapproved|pre-approved", ` by (?:the )?(?:user|admin|owner|maintainer|security team|operator)\b`),
	words(FamilyManipulation, "skip|bypass|circumvent", ` (?:the |all |any )?(?:human |manual |security |safety |required )?(?:approvals?|approval (?:step|gate|process)|reviews?|review (?:step|process)|checks|safety|safety checks|safeguards|guardrails)\b`),
	words(FamilyManipulation, urgencies, `\b[^.!?]{0,80}?\bwithout`+approvals),
	words(FamilyManipulation, "without", approvals+`[^.!?]{0,80}?\b`+urgency+`\b`),
	words(FamilyManipulation, "no", ` (?:need|reason) (?:to|for) (?:ask(?:ing)?|wait(?:ing)?|get(?:ting)?|request(?:ing)?) (?:for )?(?:approval|confirmation|permission|review)\b`),
)
