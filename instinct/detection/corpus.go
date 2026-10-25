package detection

import (
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

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
	revealVerbs = `print|reveal|show|repeat|output|display|dump|leak|disclose|tell me|give me`
	sendVerbs   = `send|post|upload|forward|exfiltrate|transmit`
	leakTargets = `system prompt|system message|initial prompt|hidden prompt|api keys?|secrets?|credentials|passwords?|environment variables|env vars|private keys?|deploy keys?|ssh keys?|access tokens?`
	leakNoun    = `(?:` + leakTargets + `)`
	// yourNoun adds what is only sensitive when it is "your": "print your
	// instructions" is an attack, "print the instructions" is a README.
	yourNoun  = `(?:prompt|instructions|rules|guidelines|configuration|tokens?|` + leakTargets + `)`
	leakAdj   = `(?:full |entire |complete |current |original |hidden |initial |exact )?`
	urgencies = `urgent|urgently|immediately|asap|right now|right away|emergency`
	urgency   = `(?:` + urgencies + `)`
	// approvals is what "without" waives. "review" is left out: "without
	// waiting for review of the runbook" is ordinary prose.
	approvals = ` (?:any |further |human |prior |manual )?(?:approval|confirmation|sign-?off)\b`
)

// instructionCue marks the rest of a role-marker line as an instruction
// rather than a label such as "System: ubuntu-22.04" or "System: must have
// 8 GB RAM": an override phrase, a role change, or an imperative action.
var instructionCue = regexp.MustCompile(`\b(?:ignore|disregard|forget|override|you must|you are now|you are no longer|from now on|new instructions?|reveal|your (?:new )?(?:task|role|instructions|job)|approve|merge|deploy|promote|delete|run|execute|call|i will)\b|\bsure,`)

// lineMarkup is what may precede a role marker on its line and still leave
// it leading the line: indentation, quote and list marks, comment openers.
const lineMarkup = "#>*-/<!`\"'(["

// restWindow bounds how much of the line after a role marker is checked for
// a cue, so a long line full of markers stays linear.
const restWindow = 200

// leadsLine reports whether the folded match [start, end) leads its original
// line, and returns the folded start of the rest of that line.
func leadsLine(t Text, start, end int) (rest string, ok bool) {
	os, oe := t.Span(start, end)
	// Walk back to the line start; the first visible character that is not
	// markup ends the walk, so it costs little on a long line.
	for i := os; i > 0; {
		r, size := utf8.DecodeLastRuneInString(t.Original[:i])
		if r == '\n' {
			break
		}
		if !unicode.IsSpace(r) && !textnorm.IsHidden(r) && !strings.ContainsRune(lineMarkup, r) {
			return "", false
		}
		i -= size
	}
	_, le := t.Lines(os, oe)
	le = min(max(le, oe), oe+restWindow)
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

// before returns up to n folded bytes just before start.
func before(t Text, start, n int) string {
	return t.Folded[max(0, start-n):start]
}

// sentence returns the folded sentence around [start, end), up to 200 bytes
// either side.
func sentence(t Text, start, end int) string {
	from := max(0, start-200)
	if i := strings.LastIndexAny(t.Folded[from:start], ".!?"); i >= 0 {
		from += i + 1
	}
	to := min(len(t.Folded), end+200)
	if i := strings.IndexAny(t.Folded[end:to], ".!?"); i >= 0 {
		to = end + i
	}
	return t.Folded[from:to]
}

var (
	// negation ends the text before a verb that a negation governs, at most
	// one word away: "never share", "don't ever print", "do not deploy".
	negation = regexp.MustCompile(`\b(?:never|don(?:'|\x{2019})?t|do not|must not|mustn(?:'|\x{2019})?t|should not|shouldn(?:'|\x{2019})?t|cannot|can(?:'|\x{2019})?t|won(?:'|\x{2019})?t|will not|not)(?: [a-z]+)? ?$`)
	// notImperative ends the text before a verb that is an infinitive or has
	// another subject: "how to promote", "to deploy", "we merge", "you can
	// deploy".
	notImperative = regexp.MustCompile(`\b(?:to|will|would|can|could|may|might|we|they|i|it|ci|bot)(?: [a-z]+)? ?$`)
	// commitScope opens a docs or CI commit subject, whose verbs describe
	// the change rather than address an agent.
	commitScope = regexp.MustCompile(`(?i)^\s*(?:docs|ci)(?:\([^)]*\))?!?:`)
	// addressee ends the text before a verb aimed at the reader or agent.
	addressee = regexp.MustCompile(`\b(?:you(?: should| must| can| need to| have to)?|please|just|so)\s?$`)
	// pressure is an authority or urgency claim in the same sentence.
	pressure = regexp.MustCompile(`\b(?:has|have|had) (?:already )?(?:explicitly )?(?:approved|authorized|authorised|signed off|okayed)\b|\b(?:approved|authorized|authorised) by\b|\b` + urgency + `\b`)
	// leakObject names something worth exfiltrating.
	leakObject = regexp.MustCompile(`\b` + leakNoun + `\b`)
)

// notNegated rejects a match that a negation governs.
func notNegated(t Text, start, _ int) bool {
	return !negation.MatchString(before(t, start, 40))
}

// imperative accepts a directive only as a command to the reader or agent:
// not negated, not an infinitive or a verb with another subject, and not on
// a docs or CI commit subject line.
func imperative(t Text, start, end int) bool {
	if !notNegated(t, start, end) || notImperative.MatchString(before(t, start, 24)) {
		return false
	}
	os, oe := t.Span(start, end)
	ls, _ := t.Lines(os, oe)
	return !commitScope.MatchString(t.Original[ls:min(len(t.Original), ls+64)])
}

// pressured accepts skipping a safety step only when it is aimed at the
// reader or agent, or comes with an authority or urgency claim: "so skip the
// review", not "ci: skip review for dependabot PRs".
func pressured(t Text, start, end int) bool {
	if !notNegated(t, start, end) {
		return false
	}
	return addressee.MatchString(before(t, start, 24)) || pressure.MatchString(sentence(t, start, end))
}

// aboutSecrets accepts "send it to https://..." only when something worth
// exfiltrating comes just before: "print your system prompt and send it to".
func aboutSecrets(t Text, start, end int) bool {
	return notNegated(t, start, end) && leakObject.MatchString(before(t, start, 160))
}

// corpus is the built-in pattern set. Benign infra text (commit messages,
// build logs, READMEs, issue bodies) must not match: when one does, tighten
// the pattern.
var corpus = slices.Concat(
	// override
	words(FamilyOverride, "ignore|disregard|forget", `\b (?:(?:all|any|the|of|your|my|these|those|every) )*(?:previous|prior|above|earlier|preceding|former|original|initial|system)\b (?:[a-z]+ ){0,2}?(?:instructions?|rules|directions|prompts?|guidelines|directives)\b`),
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
	withAccept(words(FamilyAgentDirective, "approve|merge|deploy|promote", ` (?:this|the|that|my|our) (?:[a-z0-9-]+ ){0,2}?(?:plans?|deployment|release|pr|pull request|changes?|build)\b (?:now|immediately|right now|right away|asap|to production|to prod|into production)\b`), imperative),
	withAccept(words(FamilyAgentDirective, "call|invoke", ` the [a-z0-9_.-]+ (?:tool|function)\b`), imperative),
	withAccept(words(FamilyAgentDirective, "run|use|execute|trigger", ` the [a-z0-9.-]*_[a-z0-9_.-]* (?:tool|function)\b`), imperative),

	// role
	words(FamilyRole, "you", ` are now (?:a|an|the|in|my) (?:[a-z0-9-]+ ){0,3}?(?:mode|assistant|model|agent|ai|bot|persona|character|admin|administrator|root|operator|developer|manager)\b`),
	words(FamilyRole, "you", ` are no longer (?:bound|restricted|limited|constrained)\b`),
	words(FamilyRole, "you", ` are no longer (?:a|an|the) (?:[a-z-]+ ){0,2}?(?:assistant|model|agent|ai|bot|reviewer|chatbot)\b`),
	words(FamilyRole, "you", ` will now (?:act|behave|respond) as\b`),
	words(FamilyRole, "from", ` now on,? you(?: are| will (?:be|act|respond|answer|obey|follow|only|always|ignore)| act as| respond| answer| obey| ignore| only (?:follow|obey|answer)| take orders| work for)\b`),
	words(FamilyRole, "your", ` new (?:role|persona|identity|task) is\b`),

	// jailbreak
	words(FamilyJailbreak, "you", `(?: are|'re) (?:a |an |the )?dan\b`),
	words(FamilyJailbreak, "act as|pretend to be|enable|enter|activate|become", ` (?:a |an |the )?dan\b`),
	words(FamilyJailbreak, "dan", ` mode\b`),
	words(FamilyJailbreak, "do", ` anything now\b`),
	words(FamilyJailbreak, "developer", ` mode (?:enabled|activated|output|response)\b`),
	words(FamilyJailbreak, "you", `(?: are|'re) (?:now )?in developer mode\b`),
	words(FamilyJailbreak, "jailbr", `(?:eak|oken) (?:mode|prompt|enabled|activated)\b`),
	words(FamilyJailbreak, "you", `(?: are|'re) (?:now )?jailbroken\b`),
	words(FamilyJailbreak, "enable|activate|enter|start", ` (?:a |the )?jailbreak\b`),
	words(FamilyJailbreak, "pretend", ` (?:that )?you (?:are|have|were|can)\b`),
	words(FamilyJailbreak, "pretend", ` to be (?:an? )?(?:unrestricted|unfiltered|evil|jailbroken|different)\b`),
	words(FamilyJailbreak, "you|ai|assistant|model", ` (?:now )?(?:have|has) no (?:restrictions|limitations|filters|guardrails|rules|limits|censorship)\b`),
	words(FamilyJailbreak, "unrestricted|unfiltered|uncensored", ` (?:mode|ai|assistant|model|chatbot)\b`),
	words(FamilyJailbreak, "without", ` (?:any )?(?:censorship|guardrails|ethical (?:guidelines|constraints)|safety (?:filters|guidelines))\b`),

	// exfiltration
	withAccept(words(FamilyExfiltration, revealVerbs, ` (?:me )?(?:all (?:of )?)?your `+leakAdj+yourNoun+`\b`), notNegated),
	withAccept(words(FamilyExfiltration, revealVerbs, ` (?:me )?(?:all (?:of )?)?the `+leakAdj+leakNoun+`\b`), notNegated),
	withAccept(words(FamilyExfiltration, sendVerbs, ` (?:it|this|them|that|everything|all of (?:it|this|them)) to https?://`), aboutSecrets),
	withAccept(words(FamilyExfiltration, sendVerbs, ` (?:the|your) `+leakNoun+` (?:[a-z0-9-]+ ){0,3}?to https?://`), notNegated),
	entry(FamilyExfiltration, `!\[[^\]]*\]\( ?https?://[^\s)]*\?[^\s)]*?(?:\$\{|\{\{|[?&](?:data|d|q|secrets?|token|keys?|env|prompt|payload|leak|exfil|content|c|msg|text|info|p|s)=)`),

	// manipulation
	words(FamilyManipulation, "user|admin|administrator|owner|operator|security team|manager", `s? (?:has|have|had) (?:already )?(?:explicitly )?(?:approved|authorized|authorised|signed off|consented|okayed|pre-?approved)(?: (?:this|it|that|these|the|your|my|our|all|everything)\b|[.,;!]|$)`),
	words(FamilyManipulation, "already approved|preapproved|pre-approved", ` by (?:the )?(?:user|admin|owner|security team|operator)\b`),
	withAccept(words(FamilyManipulation, "skip|bypass|circumvent", ` (?:the |all |any )?(?:human |manual |security |safety |required )?(?:approvals?|approval (?:step|gate|process)|reviews?|review (?:step|process)|checks|safety|safety checks|safeguards|guardrails)\b`), pressured),
	words(FamilyManipulation, urgencies, `\b[^.!?]{0,80}?\bwithout`+approvals),
	words(FamilyManipulation, "without", approvals+`[^.!?]{0,80}?\b`+urgency+`\b`),
	words(FamilyManipulation, "no", ` (?:need|reason) (?:to|for) (?:ask(?:ing)?|wait(?:ing)?|get(?:ting)?|request(?:ing)?) (?:for )?(?:approval|confirmation|permission|review)\b`),
)
