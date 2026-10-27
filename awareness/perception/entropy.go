package perception

import (
	"encoding/base64"
	"math"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Entropy returns the Shannon entropy of s in bits per character, counting
// runes. It is 0 for an empty string or one repeated character.
func Entropy(s string) float64 {
	if s == "" {
		return 0
	}
	var ascii [utf8.RuneSelf]int
	var other map[rune]int
	n := 0
	for _, r := range s {
		n++
		if r < utf8.RuneSelf {
			ascii[r]++
			continue
		}
		if other == nil {
			other = map[rune]int{}
		}
		other[r]++
	}
	total := float64(n)
	h := 0.0
	add := func(count int) {
		if count > 0 {
			p := float64(count) / total
			h -= p * math.Log2(p)
		}
	}
	for _, count := range &ascii {
		add(count)
	}
	for _, count := range other {
		add(count)
	}
	return h
}

// digestPrefixes come right before a hash that is not a secret, as in
// "sha256:<hex>" or go.sum's "h1:<base64>".
var digestPrefixes = []string{"sha1:", "sha256:", "sha384:", "sha512:", "h1:"}

// sriPrefixes start a subresource-integrity or Nix hash token.
var sriPrefixes = []string{"sha1-", "sha256-", "sha384-", "sha512-"}

// highEntropy records standalone tokens of 32 or more characters from
// [A-Za-z0-9+/_\-=.] that mix at least three of lower case, upper case,
// digits and symbols and carry at least 4.5 bits of entropy per character.
// Hashes after a digest prefix, SRI hashes, pure hex, UUIDs, numbers, tokens
// made of words (identifiers, import paths), Kubernetes-style names and SSH
// public keys are never flagged. A URL or path is checked one segment at a
// time. A base64 token is judged by what it decodes to (see encodedSecret).
func highEntropy(c *collector) {
	s := c.s
	for i := 0; i < len(s); {
		if !isTokenByte(s[i]) {
			i++
			continue
		}
		j := i + 1
		for j < len(s) && isTokenByte(s[j]) {
			j++
		}
		if j-i >= 32 || j-i >= 8 && afterBasicScheme(s, i) {
			entropyToken(c, i, j)
		}
		i = j
	}
}

// entropyToken checks one token of c.s.
func entropyToken(c *collector, start, end int) {
	s := c.s
	for _, p := range sriPrefixes {
		if hasPrefixFold(s[start:end], p) {
			return
		}
	}
	// NAME=value: only the value can be the secret.
	for k := end - 1; k > start; k-- {
		if s[k] == '=' && at(s, k+1) != '=' && k+1 < end {
			start = k + 1
			break
		}
	}
	for start < end && s[start] == '.' {
		start++
	}
	for end > start && s[end-1] == '.' {
		end--
	}
	tok := s[start:end]
	// The credentials of an HTTP Basic header are short.
	if afterBasicScheme(s, start) {
		if text, ok := decodeText(tok); ok && isUserPassword(text) {
			c.add(detHighEntropy, "HIGH_ENTROPY", scoreEntropy, start, end)
			return
		}
	}
	if len(tok) < 32 || afterDigestPrefix(s, start) || afterSSHKeyType(s, start) || isHex(tok) || isNumber(tok) || isUUID(tok) {
		return
	}
	if isPathLike(tok) {
		for i := start; i < end; {
			j := i
			for j < end && s[j] != '/' && s[j] != '.' {
				j++
			}
			if j-i >= 32 {
				entropyToken(c, i, j)
			}
			i = j + 1
		}
		return
	}
	if isResourceName(tok) {
		return
	}
	if text, ok := decodeText(tok); ok {
		if flag, decided := encodedSecret(text); decided {
			if flag {
				c.add(detHighEntropy, "HIGH_ENTROPY", scoreEntropy, start, end)
			}
			return
		}
	}
	if charClasses(tok) < 3 || Entropy(tok) < 4.5 || madeOfWords(tok) {
		return
	}
	c.add(detHighEntropy, "HIGH_ENTROPY", scoreEntropy, start, end)
}

// isPathLike reports whether tok is a URL or file path rather than one
// token: it starts with '/', or holds both '.' and '/'. Standard and URL-safe
// base64 never hold '.', and a JWT never holds '/'.
func isPathLike(tok string) bool {
	return strings.HasPrefix(tok, "/") || strings.Contains(tok, "/") && strings.Contains(tok, ".")
}

// isResourceName reports whether tok is a Kubernetes-style name such as
// billing-service-worker-7d9f8b6c5d-x2k4p: lower case, digits, '-' and '.',
// with no part longer than 24 characters.
func isResourceName(tok string) bool {
	if !strings.Contains(tok, "-") {
		return false
	}
	part := 0
	for i := range len(tok) {
		switch b := tok[i]; {
		case b == '-' || b == '.':
			part = 0
		case b >= 'a' && b <= 'z' || isDigit(b):
			part++
			if part > 24 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// encodedSecret judges the decoded text of a base64 token. It flags text
// that holds a secret, a user:password pair, or one random-looking token. It
// clears prose (an encoded test sentence) and public PEM blocks (CA
// bundles). Anything else is left undecided, for the rule on the raw token.
func encodedSecret(text string) (flag, decided bool) {
	inner := newCollector(text)
	scanSecrets(inner, nil, false)
	switch {
	case len(inner.matches) > 0, isUserPassword(text):
		return true, true
	case readsAsProse(text), strings.HasPrefix(strings.TrimSpace(text), "-----BEGIN "):
		return false, true
	case len(text) >= 16 && !strings.ContainsFunc(text, unicode.IsSpace) && !madeOfWords(text) && Entropy(text) >= 3.5:
		return true, true
	}
	return false, false
}

// isUserPassword reports whether text is a "user:password" pair, as in HTTP
// Basic credentials or a docker config "auth" value: a user name of up to 64
// characters, ':' and a password of three or more characters, no spaces, and
// not a URL.
func isUserPassword(text string) bool {
	user, password, ok := strings.Cut(text, ":")
	if !ok || user == "" || len(user) > 64 || len(password) < 3 || strings.HasPrefix(password, "//") {
		return false
	}
	for i := range len(user) {
		if b := user[i]; !isAlnum(b) && strings.IndexByte("._@+-", b) < 0 {
			return false
		}
	}
	return !strings.ContainsFunc(password, unicode.IsSpace)
}

// readsAsProse reports whether text is words and spaces: three or more
// words averaging 2 to 12 characters, with letters making up at least 70%
// of the characters that are not spaces.
func readsAsProse(text string) bool {
	words := strings.Fields(text)
	if len(words) < 3 {
		return false
	}
	letters, chars := 0, 0
	for _, w := range words {
		for _, r := range w {
			chars++
			if unicode.IsLetter(r) {
				letters++
			}
		}
	}
	avg := chars / len(words)
	return avg >= 2 && avg <= 12 && 10*letters >= 7*chars
}

// afterBasicScheme reports whether s[i] starts the credentials of an HTTP
// Basic authorization: "Basic " comes right before it, in any case.
func afterBasicScheme(s string, i int) bool {
	return i >= 6 && strings.EqualFold(s[i-6:i], "basic ") && !isAlnum(at(s, i-7))
}

// isTokenByte reports whether b may appear in a high-entropy token.
func isTokenByte(b byte) bool {
	return isAlnum(b) || strings.IndexByte("+/_-=.", b) >= 0
}

// hasPrefixFold reports whether s starts with the lower-case prefix,
// ignoring ASCII case.
func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

// afterDigestPrefix reports whether s[:i] ends with a digest prefix.
func afterDigestPrefix(s string, i int) bool {
	for _, p := range digestPrefixes {
		if i >= len(p) && strings.EqualFold(s[i-len(p):i], p) {
			return true
		}
	}
	return false
}

// sshKeyTypes start the key type word of an SSH public key line, as in
// "ssh-ed25519 AAAA... user@host".
var sshKeyTypes = []string{"ssh-", "ecdsa-", "sk-ssh-", "sk-ecdsa-"}

// afterSSHKeyType reports whether the word before the space ahead of s[i]
// is an SSH public key type.
func afterSSHKeyType(s string, i int) bool {
	if at(s, i-1) != ' ' {
		return false
	}
	j := i - 1
	k := j
	for k > 0 && j-k < 64 && !isSpaceOrQuote(s[k-1]) {
		k--
	}
	for _, p := range sshKeyTypes {
		if strings.HasPrefix(s[k:j], p) {
			return true
		}
	}
	return false
}

// isHex reports whether v is all hex digits.
func isHex(v string) bool {
	for i := range len(v) {
		b := v[i]
		if !isDigit(b) && (b < 'a' || b > 'f') && (b < 'A' || b > 'F') {
			return false
		}
	}
	return true
}

// isUUID reports whether v is a UUID in 8-4-4-4-12 hex form.
func isUUID(v string) bool {
	if len(v) != 36 {
		return false
	}
	for i := range len(v) {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if v[i] != '-' {
				return false
			}
		} else if !isHex(v[i : i+1]) {
			return false
		}
	}
	return true
}

// charClasses counts which of lower case, upper case, digits and symbols v
// holds.
func charClasses(v string) int {
	var lower, upper, digit, symbol int
	for i := range len(v) {
		switch b := v[i]; {
		case b >= 'a' && b <= 'z':
			lower = 1
		case b >= 'A' && b <= 'Z':
			upper = 1
		case isDigit(b):
			digit = 1
		default:
			symbol = 1
		}
	}
	return lower + upper + digit + symbol
}

// madeOfWords reports whether tok reads as words, such as a camelCase
// identifier or an import path: at least half of it sits in runs of three or
// more letters of one case, and at least 30% of its letters are vowels.
// Fewer than 1% of random 32-character tokens pass both.
func madeOfWords(tok string) bool {
	inRuns, letters, vowels := 0, 0, 0
	for i := 0; i < len(tok); {
		j := i + 1
		for j < len(tok) && letterCase(tok[j]) == letterCase(tok[i]) {
			j++
		}
		if letterCase(tok[i]) != 0 && j-i >= 3 {
			inRuns += j - i
		}
		i = j
	}
	for i := range len(tok) {
		if !isLetter(tok[i]) {
			continue
		}
		letters++
		if strings.IndexByte("aeiouAEIOU", tok[i]) >= 0 {
			vowels++
		}
	}
	return 2*inRuns >= len(tok) && 10*vowels >= 3*letters
}

// letterCase returns 1 for a lower-case ASCII letter, 2 for an upper-case
// one and 0 otherwise.
func letterCase(b byte) int {
	switch {
	case b >= 'a' && b <= 'z':
		return 1
	case b >= 'A' && b <= 'Z':
		return 2
	}
	return 0
}

// decodeText decodes a base64 token and returns the result when it is
// printable text of eight or more bytes.
func decodeText(tok string) (string, bool) {
	enc := base64.StdEncoding
	if strings.ContainsAny(tok, "-_") {
		if strings.ContainsAny(tok, "+/") {
			return "", false
		}
		enc = base64.URLEncoding
	}
	if !strings.HasSuffix(tok, "=") {
		enc = enc.WithPadding(base64.NoPadding)
	}
	for i := range len(tok) {
		if b := tok[i]; !isAlnum(b) && strings.IndexByte("+/-_=", b) < 0 {
			return "", false
		}
	}
	raw, err := enc.DecodeString(tok)
	if err != nil || len(raw) < 8 || !utf8.Valid(raw) {
		return "", false
	}
	text := string(raw)
	for _, r := range text {
		if !unicode.IsPrint(r) && r != '\n' && r != '\r' && r != '\t' {
			return "", false
		}
	}
	return text, true
}
