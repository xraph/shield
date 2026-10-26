package perception

import (
	"regexp"
	"slices"
	"strings"
)

// Built-in secret detector names. The names avoid the words gosec reads as
// credentials.
const (
	detAWSAccess   = "aws_access_key"
	detAWSSecret   = "aws_secret_key"
	detGitHub      = "github_token"
	detGitLab      = "gitlab_token"
	detSlack       = "slack_token"
	detStripe      = "stripe_key"
	detGoogle      = "google_api_key"
	detAnthropic   = "anthropic_key"
	detOpenAI      = "openai_key"
	detPrivateKey  = "private_key"
	detJWT         = "jwt"
	detConnection  = "connection_string"
	detAssignment  = "generic_assignment"
	detHighEntropy = "high_entropy"
)

// Scores: a known format is certain, an assignment to a credential-named key
// is likely, and a random-looking token is a guess.
const (
	scoreKnown      = 1.0
	scoreAssignment = 0.8
	scoreEntropy    = 0.6
)

// BuiltinSecrets returns the built-in secret detector names.
func BuiltinSecrets() []string {
	return []string{
		detAWSAccess, detAWSSecret, detGitHub, detGitLab, detSlack, detStripe,
		detGoogle, detAnthropic, detOpenAI, detPrivateKey, detJWT, detConnection,
		detAssignment, detHighEntropy,
	}
}

// Secrets runs the named built-in secret detectors over text. Empty
// detectors runs them all; unknown names are ignored. Known formats score 1,
// generic_assignment 0.8 and high_entropy 0.6. Where matches overlap only
// the highest-scoring one is kept, so one secret is one match.
func Secrets(text string, detectors []string) []Match {
	c := newCollector(text)
	scanSecrets(c, detectors, true)
	return c.result()
}

// scanSecrets runs the enabled detectors; high_entropy only when entropy is
// set, so decoded text is scanned one level deep.
func scanSecrets(c *collector, detectors []string, entropy bool) {
	for _, f := range formats {
		if enabled(detectors, f.name) {
			f.scan(c)
		}
	}
	if enabled(detectors, detPrivateKey) {
		privateKeys(c)
	}
	if enabled(detectors, detConnection) {
		connectionStrings(c)
		mysqlDSNs(c)
	}
	if aws, generic := enabled(detectors, detAWSSecret), enabled(detectors, detAssignment); aws || generic {
		assignments(c, aws, generic)
	}
	if entropy && enabled(detectors, detHighEntropy) {
		highEntropy(c)
	}
}

// format is a known token format.
type format struct {
	name, typ string
	// hints are literals of which at least one must be in the text for the
	// pattern to run, which keeps clean text cheap.
	hints []string
	re    *regexp.Regexp
	// glued rejects a match right after a letter or digit.
	glued bool
	// exact rejects a fixed-length match followed by a letter, a digit or
	// one of tail.
	exact bool
	tail  string
}

// formats are the known token formats. A pattern with a named group
// "secret" redacts that group only.
var formats = []format{
	{name: detAWSAccess, typ: "AWS_ACCESS_KEY", hints: []string{"AKIA", "ASIA", "ABIA", "ACCA", "A3T"},
		re: regexp.MustCompile(`(?:AKIA|ASIA|ABIA|ACCA|A3T[A-Z0-9])[A-Z0-9]{16}`), glued: true, exact: true},
	{name: detGitHub, typ: "GITHUB_TOKEN", hints: []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"},
		re: regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,251}|github_pat_[A-Za-z0-9_]{82,}`), glued: true},
	{name: detGitLab, typ: "GITLAB_TOKEN", hints: []string{"glpat-", "gldt-", "glrt-", "glptt-", "glsoat-", "glcbt-"},
		re: regexp.MustCompile(`gl(?:pat|dt|rt|ptt|soat|cbt)-[A-Za-z0-9_\-]{20,}`), glued: true},
	{name: detSlack, typ: "SLACK_TOKEN", hints: []string{"xox", "xapp-"},
		re: regexp.MustCompile(`xox[abposre]-[A-Za-z0-9\-]{10,}|xapp-\d-[A-Za-z0-9\-]{10,}`), glued: true},
	{name: detSlack, typ: "SLACK_TOKEN", hints: []string{"hooks.slack.com"},
		re: regexp.MustCompile(`hooks\.slack\.com/(?:services|workflows|triggers)/(?P<secret>[A-Za-z0-9_/]{20,})`)},
	{name: detStripe, typ: "STRIPE_KEY", hints: []string{"sk_live_", "sk_test_", "rk_live_", "rk_test_", "whsec_"},
		re: regexp.MustCompile(`[sr]k_(?:live|test)_[A-Za-z0-9]{24,}|whsec_[A-Za-z0-9+/=]{32,}`), glued: true},
	{name: detGoogle, typ: "GOOGLE_API_KEY", hints: []string{"AIza"},
		re: regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`), glued: true, exact: true, tail: "_-"},
	{name: detAnthropic, typ: "ANTHROPIC_KEY", hints: []string{"sk-ant-"},
		re: regexp.MustCompile(`sk-ant-[a-z0-9]{2,12}-[A-Za-z0-9_\-]{32,}`), glued: true},
	{name: detOpenAI, typ: "OPENAI_KEY", hints: []string{"sk-proj-", "sk-svcacct-", "sk-admin-"},
		re: regexp.MustCompile(`sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{20,}`), glued: true},
	{name: detOpenAI, typ: "OPENAI_KEY", hints: []string{"sk-"},
		re: regexp.MustCompile(`sk-[A-Za-z0-9]{48}`), glued: true, exact: true, tail: "_-"},
	{name: detJWT, typ: "JWT", hints: []string{"eyJ"},
		re: regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*`), glued: true},
}

// scan records every match of f that passes its edge checks.
func (f format) scan(c *collector) {
	s := c.s
	if !containsAny(s, f.hints) {
		return
	}
	group := f.re.SubexpIndex(redactGroup)
	for _, loc := range f.re.FindAllStringSubmatchIndex(s, -1) {
		start, end := loc[0], loc[1]
		if f.glued && isAlnum(at(s, start-1)) {
			continue
		}
		if b := at(s, end); f.exact && (isAlnum(b) || b != 0 && strings.IndexByte(f.tail, b) >= 0) {
			continue
		}
		if group > 0 && loc[2*group] >= 0 {
			start, end = loc[2*group], loc[2*group+1]
		}
		c.add(f.name, f.typ, scoreKnown, start, end)
	}
}

// containsAny reports whether s holds any of subs.
func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// pemBegin is the BEGIN line of a private key. The labels are a fixed set,
// which bounds the END searches.
var pemBegin = regexp.MustCompile(`-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?)-----`)

// privateKeys records each private key from its BEGIN line through the
// matching END line. A block with no END line runs through the header and
// base64 lines that follow it, so a truncated key still loses its body.
func privateKeys(c *collector) {
	s := c.s
	if !strings.Contains(s, "PRIVATE KEY") {
		return
	}
	noEnd := map[string]bool{}
	last := 0
	for _, loc := range pemBegin.FindAllStringSubmatchIndex(s, -1) {
		start := loc[0]
		if start < last {
			continue
		}
		label := s[loc[2]:loc[3]]
		end := -1
		if !noEnd[label] {
			marker := "-----END " + label + "-----"
			if i := strings.Index(s[loc[1]:], marker); i >= 0 {
				end = loc[1] + i + len(marker)
			} else {
				noEnd[label] = true
			}
		}
		if end < 0 {
			end = pemBodyEnd(s, loc[1])
		}
		c.add(detPrivateKey, "PRIVATE_KEY", scoreKnown, start, end)
		last = end
	}
}

// pemBodyEnd returns where the body of a PEM block that starts at from ends:
// after its last armor header or base64 line. Lines break at a newline, or
// at a literal "\n" when the key sits escaped in a JSON or YAML string. A
// cut-off last line still counts when it opens with 16 or more base64
// characters, or with any before the closing quote or backslash of an
// escaped string.
func pemBodyEnd(s string, from int) int {
	end, i := from, from
	sep := "\n"
	switch {
	case strings.HasPrefix(s[i:], "\r\n"):
		i += 2
	case at(s, i) == '\n':
		i++
	case strings.HasPrefix(s[i:], `\n`):
		sep = `\n`
		i += 2
	default:
		return end
	}
	body := false
	for i < len(s) {
		lineEnd := strings.Index(s[i:], sep)
		if lineEnd < 0 {
			lineEnd = len(s)
		} else {
			lineEnd += i
		}
		line := strings.TrimRight(s[i:lineEnd], "\r")
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "" && !body:
		case !body && pemHeader.MatchString(trimmed):
			end = i + len(line)
		case isBase64Line(trimmed):
			body = true
			end = i + len(line)
		default:
			n := 0
			for n < len(line) && isBase64Byte(line[n]) {
				n++
			}
			if n >= 16 || n > 0 && (at(line, n) == '"' || at(line, n) == '\\') {
				end = i + n
			}
			return end
		}
		i = lineEnd + len(sep)
	}
	return end
}

// pemHeader is an armor header line such as "Proc-Type: 4,ENCRYPTED".
var pemHeader = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]*: `)

// isBase64Line reports whether line is PEM body: 16 or more base64
// characters, or a shorter padded or checksum line.
func isBase64Line(line string) bool {
	if line == "" {
		return false
	}
	for i := range len(line) {
		if !isBase64Byte(line[i]) {
			return false
		}
	}
	return len(line) >= 16 || strings.HasPrefix(line, "=") || strings.HasSuffix(line, "=")
}

// isBase64Byte reports whether b is in the standard base64 alphabet or '='.
func isBase64Byte(b byte) bool {
	return isAlnum(b) || b == '+' || b == '/' || b == '='
}

// connectionStrings records the password of every URL with user info, such
// as postgres://app:PASSWORD@db:5432/x. Placeholder passwords are skipped.
func connectionStrings(c *collector) {
	s := c.s
	for from := 0; from < len(s); {
		i := strings.Index(s[from:], "://")
		if i < 0 {
			return
		}
		i += from
		from = i + 3
		k := i
		for k > 0 && i-k < 32 && isSchemeByte(s[k-1]) {
			k--
		}
		for k < i && !isLetter(s[k]) {
			k++
		}
		if k == i {
			continue
		}
		user := i + 3
		u := scanUntil(s, user, ":/@?#")
		if at(s, u) != ':' {
			continue
		}
		pw := u + 1
		e := scanUntil(s, pw, "/@?#")
		if e == pw || at(s, e) != '@' || !isAlnum(at(s, e+1)) && at(s, e+1) != '[' {
			continue
		}
		if isPlaceholder(s[pw:e]) {
			continue
		}
		c.add(detConnection, "CONNECTION_STRING", scoreKnown, pw, e)
		from = e + 1
	}
}

// dsnHosts follow the password of a Go MySQL DSN such as
// app:PASSWORD@tcp(db:3306)/app, which has no scheme.
var dsnHosts = []string{"@tcp(", "@unix("}

// mysqlDSNs records the password of every Go MySQL DSN.
func mysqlDSNs(c *collector) {
	s := c.s
	for _, host := range dsnHosts {
		for from := 0; from < len(s); {
			i := strings.Index(s[from:], host)
			if i < 0 {
				break
			}
			i += from
			from = i + len(host)
			pw := i
			for pw > 0 && i-pw < 256 && !isSpaceOrQuote(s[pw-1]) && strings.IndexByte(":@/", s[pw-1]) < 0 {
				pw--
			}
			if pw == i || at(s, pw-1) != ':' || !isKeyByte(at(s, pw-2)) || isPlaceholder(s[pw:i]) {
				continue
			}
			c.add(detConnection, "CONNECTION_STRING", scoreKnown, pw, i)
		}
	}
}

// scanUntil returns the offset of the first byte from i on that is a space,
// a quote or in stops, looking at most 256 bytes ahead.
func scanUntil(s string, i int, stops string) int {
	j := i
	for j < len(s) && j-i < 256 && !isSpaceOrQuote(s[j]) && strings.IndexByte(stops, s[j]) < 0 {
		j++
	}
	return j
}

// isSchemeByte reports whether b may appear in a URL scheme.
func isSchemeByte(b byte) bool {
	return isAlnum(b) || b == '+' || b == '.' || b == '-'
}

// isLetter reports whether b is an ASCII letter.
func isLetter(b byte) bool {
	return isAlnum(b) && !isDigit(b)
}

// isSpaceOrQuote reports whether b ends a value: ASCII whitespace or a quote.
func isSpaceOrQuote(b byte) bool {
	switch b {
	case ' ', '\t', '\n', '\r', '\v', '\f', '"', '\'', '`':
		return true
	}
	return false
}

// keyWords are the lower-case key words of a credential assignment.
var keyWords = []string{
	"api_key", "api-key", "apikey", "secret", "token", "password", "passwd", "pwd", "credential",
	"access_key", "access-key", "accesskey", "private_key", "private-key", "privatekey",
}

// keyEndings mark a key that names something about a credential rather than
// holding one, such as secretName or token_url.
var keyEndings = []string{
	"name", "names", "ref", "file", "path", "dir", "url", "uri", "endpoint", "type", "id", "ids",
	"count", "len", "length", "size", "ttl", "timeout", "expiry", "expires", "expiration", "limit",
	"header", "field", "env", "var", "prefix", "policy", "version", "mode", "enabled", "required",
}

// assignments records the values of assignments to credential-named keys:
// a key holding a key word, ':' or '=' (or ":=", "=>", "=="), optional
// quotes, then a value of eight or more non-space characters with entropy
// of at least 3. Placeholders, numbers, code and paths are not values.
// With aws set it also records an AWS secret access key: an assignment to a
// key holding "aws" then "secret" of exactly 40 base64 characters, scored as
// a known format.
func assignments(c *collector, aws, generic bool) {
	s := c.s
	for i := 0; i < len(s); {
		k := strings.IndexAny(s[i:], ":=")
		if k < 0 {
			return
		}
		op := i + k
		i = op + 1
		opEnd := op + 1
		switch {
		case s[op] == ':' && at(s, op+1) == '/':
			continue
		case s[op] == ':' && at(s, op+1) == '=', s[op] == '=' && (at(s, op+1) == '>' || at(s, op+1) == '='):
			opEnd++
		}
		key, keyStart := keyBefore(s, op)
		awsKey := aws && isAWSSecretKey(key)
		// In "arn:aws:secretsmanager:...:secret:name" the ':' joins
		// segments; it is not an assignment.
		credential := generic && credentialKey(key) && (s[op] != ':' || at(s, keyStart-1) != ':')
		if !awsKey && !credential {
			continue
		}
		start, end := valueAfter(s, opEnd)
		i = max(i, end)
		v := s[start:end]
		if awsKey && len(v) == 40 && isStdBase64(v) {
			c.add(detAWSSecret, "AWS_SECRET_KEY", scoreKnown, start, end)
		}
		if credential && isCredentialValue(v) {
			c.add(detAssignment, "GENERIC_ASSIGNMENT", scoreAssignment, start, end)
		}
	}
}

// isAWSSecretKey reports whether key names an AWS secret access key: "aws",
// then "secret" at most 20 bytes later, then at most 20 more bytes, in any
// case, as in AWS_SECRET_ACCESS_KEY or aws_secret_key.
func isAWSSecretKey(key string) bool {
	lower := strings.ToLower(key)
	for from := 0; ; {
		i := strings.Index(lower[from:], "aws")
		if i < 0 {
			return false
		}
		i += from + 3
		from = i
		if j := strings.Index(lower[i:min(len(lower), i+20+6)], "secret"); j >= 0 && len(lower)-(i+j+6) <= 20 {
			return true
		}
	}
}

// isStdBase64 reports whether v is all standard base64 letters, digits, '+'
// and '/'.
func isStdBase64(v string) bool {
	for i := range len(v) {
		if b := v[i]; !isAlnum(b) && b != '+' && b != '/' {
			return false
		}
	}
	return true
}

// keyBefore returns the key that ends just before the operator at op and
// where it starts, skipping blanks and a closing quote, at most 64 bytes
// long.
func keyBefore(s string, op int) (key string, start int) {
	j := op
	for j > 0 && (s[j-1] == ' ' || s[j-1] == '\t') {
		j--
	}
	if j > 0 && (s[j-1] == '"' || s[j-1] == '\'') {
		j--
	}
	k := j
	for k > 0 && j-k < 64 && isKeyByte(s[k-1]) {
		k--
	}
	return s[k:j], k
}

// isKeyByte reports whether b may appear in an assignment key.
func isKeyByte(b byte) bool {
	return isAlnum(b) || b == '_' || b == '-' || b == '.'
}

// credentialKey reports whether key holds a key word as a whole part: the
// word ends the key, is followed by "s", a separator or digit, or by an
// upper-case letter after a lower-case one (camelCase). A key that ends in
// a word from keyEndings after the key word names something else.
func credentialKey(key string) bool {
	if key == "" {
		return false
	}
	lower := strings.ToLower(key)
	for _, w := range keyWords {
		for from := 0; ; {
			i := strings.Index(lower[from:], w)
			if i < 0 {
				break
			}
			i += from
			from = i + 1
			after := i + len(w)
			rest := key[after:]
			if !wordEnds(key, after) {
				continue
			}
			if rest == "" || strings.EqualFold(rest, "s") {
				return true
			}
			return !slices.Contains(keyEndings, lastWord(key))
		}
	}
	return false
}

// wordEnds reports whether a key word that ends at i in key is a whole part.
func wordEnds(key string, i int) bool {
	if i == len(key) || strings.EqualFold(key[i:], "s") {
		return true
	}
	next := key[i]
	switch {
	case !isLetter(next):
		return true
	case next >= 'A' && next <= 'Z':
		prev := key[i-1]
		return prev >= 'a' && prev <= 'z'
	}
	return false
}

// lastWord returns the last word of key in lower case: the trailing run of
// letters and digits of one case, with the capital that starts a camelCase
// word.
func lastWord(key string) string {
	i := len(key)
	upper := i > 0 && key[i-1] >= 'A' && key[i-1] <= 'Z'
	for i > 0 && (isDigit(key[i-1]) || isLetter(key[i-1]) && (key[i-1] >= 'A' && key[i-1] <= 'Z') == upper) {
		i--
	}
	if !upper && i > 0 && key[i-1] >= 'A' && key[i-1] <= 'Z' {
		i--
	}
	return strings.ToLower(key[i:])
}

// valueAfter returns the value that starts after an operator ending at i:
// blanks and an opening quote are skipped, and the value runs to a space or
// quote, or for an unquoted value also to ',' or ';'. Trailing '.', '\' and
// unbalanced closing brackets are trimmed.
func valueAfter(s string, i int) (start, end int) {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	quote := byte(0)
	if b := at(s, i); b == '"' || b == '\'' {
		quote = b
		i++
	}
	end = i
	for end < len(s) && !isSpaceOrQuote(s[end]) && (quote != 0 || s[end] != ',' && s[end] != ';') {
		end++
	}
	// open counts '(' minus ')', '[' minus ']' and '{' minus '}' in the value.
	var open [3]int
	for k := i; k < end; k++ {
		if b, d := bracket(s[k]); d != 0 {
			open[b] += d
		}
	}
	for end > i {
		last := s[end-1]
		b, d := bracket(last)
		switch {
		case last == '.' || last == '\\':
		case d < 0 && open[b] < 0:
			open[b]++
		default:
			return i, end
		}
		end--
	}
	return i, end
}

// bracket returns which bracket pair b belongs to and +1 for an opening
// bracket, -1 for a closing one, or 0 for any other byte.
func bracket(b byte) (pair, delta int) {
	switch b {
	case '(':
		return 0, 1
	case ')':
		return 0, -1
	case '[':
		return 1, 1
	case ']':
		return 1, -1
	case '{':
		return 2, 1
	case '}':
		return 2, -1
	}
	return 0, 0
}

// isCredentialValue reports whether an assigned value looks like a secret.
func isCredentialValue(v string) bool {
	switch {
	case len(v) < 8, isPlaceholder(v), isNumber(v), looksLikeCode(v), looksLikePath(v):
		return false
	}
	return Entropy(v) >= 3.0
}

// placeholderName is a redaction placeholder or an all-caps template name
// such as "[EMAIL_1]" or "GITHUB_TOKEN_1".
var placeholderName = regexp.MustCompile(`^\[?[A-Z][A-Z0-9_]*_\d+\]?$`)

// envReference is "$NAME" or "%NAME%".
var envReference = regexp.MustCompile(`^(?:\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%)$`)

// isPlaceholder reports whether v stands in for a value rather than being
// one: "${...}", "{{...}}", "$(...)", "<...>", all '*', "xxx...", "$NAME",
// "%NAME%", placeholders like "[EMAIL_1]", or a value made only of
// placeholder words with at least one marker, such as "changeme",
// "example-password", "[REDACTED]" or "your_api_key_here". A real value that
// merely contains such a word, like "Example!2026xyz", is not one.
func isPlaceholder(v string) bool {
	lower := strings.ToLower(v)
	switch {
	case strings.HasPrefix(v, "${"), strings.HasPrefix(v, "{{"), strings.HasPrefix(v, "$("),
		strings.HasPrefix(v, "<") && strings.HasSuffix(v, ">"),
		strings.Trim(v, "*") == "",
		strings.HasPrefix(lower, "xxx"),
		envReference.MatchString(v), placeholderName.MatchString(v):
		return true
	}
	parts := strings.FieldsFunc(lower, func(r rune) bool { return strings.ContainsRune("-_. []<>", r) })
	marked := false
	for _, part := range parts {
		switch {
		case slices.Contains(placeholderMarkers, part):
			marked = true
		case !slices.Contains(placeholderWords, part):
			return false
		}
	}
	return marked
}

// placeholderMarkers are the words that make a value a placeholder.
var placeholderMarkers = []string{
	"example", "examples", "changeme", "redacted", "placeholder", "your", "dummy", "sample", "fake",
	"insert", "replace", "todo",
}

// placeholderWords may sit next to a marker in a placeholder value.
var placeholderWords = []string{
	"my", "here", "value", "secret", "password", "passwd", "pass", "pwd", "token", "key", "api", "access",
	"auth", "client", "user", "username", "name", "db", "database", "test", "goes", "with", "this", "a", "an",
	"the", "me", "change",
}

// isNumber reports whether v is all digits.
func isNumber(v string) bool {
	for i := range len(v) {
		if !isDigit(v[i]) {
			return false
		}
	}
	return v != ""
}

// memberAccess is a dotted identifier such as config.Database.Password.
var memberAccess = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+$`)

// looksLikeCode reports whether v is a call or a member access rather than
// a literal.
func looksLikeCode(v string) bool {
	return strings.Contains(v, "(") || memberAccess.MatchString(v)
}

// looksLikePath reports whether v is a lower-case file path.
func looksLikePath(v string) bool {
	if !strings.HasPrefix(v, "/") && !strings.HasPrefix(v, "./") && !strings.HasPrefix(v, "../") && !strings.HasPrefix(v, "~/") {
		return false
	}
	for i := range len(v) {
		b := v[i]
		if (b < 'a' || b > 'z') && !isDigit(b) && strings.IndexByte("._/~-", b) < 0 {
			return false
		}
	}
	return true
}
