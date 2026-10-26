package perception

import (
	"net/netip"
	"regexp"
	"strings"
)

// Built-in PII detector names.
const (
	piiEmail      = "email"
	piiPhone      = "phone"
	piiSSN        = "ssn"
	piiCreditCard = "credit_card"
	piiIBAN       = "iban"
	piiIPAddress  = "ip_address"
)

// BuiltinPII returns the built-in PII detector names.
func BuiltinPII() []string {
	return []string{piiEmail, piiPhone, piiSSN, piiCreditCard, piiIBAN, piiIPAddress}
}

// PII runs the named built-in PII detectors over text. Empty detectors runs
// every built-in except ip_address; unknown names are ignored. Every match
// scores 1, and overlapping matches keep the longest.
func PII(text string, detectors []string) []Match {
	c := newCollector(text)
	on := func(name string) bool {
		if len(detectors) == 0 {
			return name != piiIPAddress
		}
		return enabled(detectors, name)
	}
	if on(piiEmail) {
		emails(c)
	}
	phone, ssn, card, ip := on(piiPhone), on(piiSSN), on(piiCreditCard), on(piiIPAddress)
	if phone || ssn || card || ip {
		numericSpans(c.s, func(from, to, digits int) {
			if phone {
				phones(c, from, to, digits)
			}
			if ssn {
				ssns(c, from, to, digits)
			}
			if card {
				creditCards(c, from, to, digits)
			}
			if ip {
				ipv4(c, from, to, digits)
			}
		})
	}
	if on(piiIBAN) {
		ibans(c)
	}
	if ip {
		ipv6(c)
	}
	return c.result()
}

// emails finds addresses by their '@': a local part of up to 64 characters
// before it and a domain after it that ends in an alphabetic top-level label.
// A host followed by ':' and a path is an scp-style remote such as
// "git@github.com:org/repo", and "user:password@host" inside a URL is a
// connection string; neither is an address.
func emails(c *collector) {
	s := c.s
	for from := 0; from < len(s); {
		i := strings.IndexByte(s[from:], '@')
		if i < 0 {
			return
		}
		i += from
		from = i + 1
		start := i
		for start > 0 && i-start < 64 && isLocalByte(s[start-1]) {
			start--
		}
		for start < i && s[start] == '.' {
			start++
		}
		if start == i || s[i-1] == '.' || at(s, start-1) == ':' && inURL(s, start-1) {
			continue
		}
		stop := i + 1
		for stop < len(s) && stop-i <= 253 && (isAlnum(s[stop]) || s[stop] == '-' || s[stop] == '.') {
			stop++
		}
		n := domainLength(s[i+1 : stop])
		if n == 0 {
			continue
		}
		end := i + 1 + n
		if at(s, end) == ':' && isPathStart(at(s, end+1)) {
			continue
		}
		c.add(piiEmail, "EMAIL", 1, start, end)
	}
}

// inURL reports whether offset i sits in a URL: "://" comes before it with
// no space between, looking at most 256 bytes back.
func inURL(s string, i int) bool {
	from := max(0, i-256)
	if k := strings.LastIndexAny(s[from:i], " \t\n\r\"'`<>"); k >= 0 {
		from += k + 1
	}
	return strings.Contains(s[from:i], "://")
}

// isLocalByte reports whether b may appear in the local part of an address.
func isLocalByte(b byte) bool {
	return isAlnum(b) || strings.IndexByte("._%+-", b) >= 0
}

// isPathStart reports whether b can start the path of an scp-style remote.
func isPathStart(b byte) bool {
	return b != 0 && (isAlnum(b) || strings.IndexByte("~/._-", b) >= 0)
}

// domainLength returns the length of the longest prefix of d that is a
// domain of two or more labels ending in an alphabetic label of two or more
// letters, or 0.
func domainLength(d string) int {
	best, labels := 0, 0
	for p := 0; p < len(d); {
		q := strings.IndexByte(d[p:], '.')
		if q < 0 {
			q = len(d)
		} else {
			q += p
		}
		label := d[p:q]
		if label == "" || label[0] == '-' || label[len(label)-1] == '-' {
			break
		}
		labels++
		if labels >= 2 && len(label) >= 2 && isLetters(label) {
			best = q
		}
		p = q + 1
	}
	return best
}

// isLetters reports whether s is all ASCII letters.
func isLetters(s string) bool {
	for i := range len(s) {
		if !isLetter(s[i]) {
			return false
		}
	}
	return true
}

// numericSpans calls fn with each maximal run of digits, spaces and
// "-.()+" that holds four or more digits, and its digit count. Every number
// the digit-based detectors look for lies inside one such run, so their
// patterns only ever run on these short spans.
func numericSpans(s string, fn func(from, to, digits int)) {
	for i := 0; i < len(s); {
		if !isNumericByte(s[i]) {
			i++
			continue
		}
		j, digits := i, 0
		for j < len(s) && isNumericByte(s[j]) {
			if isDigit(s[j]) {
				digits++
			}
			j++
		}
		if digits >= 4 {
			fn(i, j, digits)
		}
		i = j
	}
}

// isNumericByte reports whether b may appear in a written number.
func isNumericByte(b byte) bool {
	return isDigit(b) || strings.IndexByte(" -.()+", b) >= 0
}

// findIn returns the matches of re in s[from:to] as offsets into s.
func findIn(re *regexp.Regexp, s string, from, to int) [][]int {
	locs := re.FindAllStringIndex(s[from:to], -1)
	for _, loc := range locs {
		loc[0] += from
		loc[1] += from
	}
	return locs
}

// phoneIntlArea is '+', a country code and an area code in parentheses.
var phoneIntlArea = regexp.MustCompile(`\+\d{1,3}[ .\-]?\(\d{1,4}\)(?:[ .\-]?\d){4,11}`)

// nanpShapes are the North American layouts: 'd' is a digit, anything else
// itself.
var nanpShapes = []string{"ddd-ddd-dddd", "(ddd) ddd-dddd", "(ddd)ddd-dddd"}

// phones finds, in the numeric span s[from:to], international numbers ('+'
// and 8 to 15 digits with optional single separators, or with an area code
// in parentheses) and North American numbers, none of them inside a longer
// run of digits.
func phones(c *collector, from, to, digits int) {
	s := c.s
	if digits >= 8 {
		for i := from; i < to; i++ {
			if s[i] != '+' || isAlnum(at(s, i-1)) || at(s, i-1) == '+' {
				continue
			}
			if end := intlPhoneEnd(s, i); end > 0 {
				c.add(piiPhone, "PHONE", 1, i, end)
				i = end - 1
			}
		}
		if strings.IndexByte(s[from:to], '(') >= 0 {
			for _, loc := range findIn(phoneIntlArea, s, from, to) {
				start, end := loc[0], loc[1]
				if n := countDigits(s[start:end]); n < 8 || n > 15 {
					continue
				}
				if b := at(s, start-1); isAlnum(b) || b == '+' || !digitRunEnds(s, end, " .-") {
					continue
				}
				c.add(piiPhone, "PHONE", 1, start, end)
			}
		}
	}
	if digits < 10 {
		return
	}
	for i := from; i < to; i++ {
		if s[i] != '(' && (!isDigit(s[i]) || !digitRunStarts(s, i)) {
			continue
		}
		for _, shape := range nanpShapes {
			if end := i + len(shape); hasShape(s, i, shape) && digitRunEnds(s, end, "-.") && (s[i] == '(' || digitRunStarts(s, i)) {
				c.add(piiPhone, "PHONE", 1, i, end)
				i = end - 1
				break
			}
		}
	}
}

// intlPhoneEnd returns the end of the international number whose '+' is at
// i: digits joined by single spaces, dots or dashes, 8 to 15 of them, with
// no more digits run on. It returns -1 for anything else.
func intlPhoneEnd(s string, i int) int {
	j, digits := i+1, 0
	for j < len(s) {
		switch {
		case isDigit(s[j]):
			digits++
			j++
		case digits > 0 && strings.IndexByte(" .-", s[j]) >= 0 && isDigit(at(s, j+1)):
			j++
		default:
			if digits < 8 || digits > 15 || isAlnum(at(s, j)) {
				return -1
			}
			return j
		}
	}
	if digits < 8 || digits > 15 {
		return -1
	}
	return j
}

// hasShape reports whether s at i follows shape, where 'd' is any digit and
// every other byte stands for itself.
func hasShape(s string, i int, shape string) bool {
	if i+len(shape) > len(s) {
		return false
	}
	for k := range len(shape) {
		b := s[i+k]
		if shape[k] == 'd' && !isDigit(b) || shape[k] != 'd' && b != shape[k] {
			return false
		}
	}
	return true
}

// ssns finds US social security numbers in the numeric span s[from:to]:
// ddd-dd-dddd with area 001 to 899 except 666, group 01 to 99 and serial
// 0001 to 9999, outside any longer run of digits.
func ssns(c *collector, from, to, digits int) {
	s := c.s
	if digits < 9 {
		return
	}
	for i := from; i+11 <= to; i++ {
		if !isDigit(s[i]) || !digitRunStarts(s, i) || !hasShape(s, i, "ddd-dd-dddd") || !digitRunEnds(s, i+11, "-.") {
			continue
		}
		v := s[i : i+11]
		area, group, serial := v[:3], v[4:6], v[7:]
		if area == "000" || area == "666" || area[0] == '9' || group == "00" || serial == "0000" {
			continue
		}
		c.add(piiSSN, "SSN", 1, i, i+11)
		i += 10
	}
}

// digitRunStarts reports whether a number starting at i is not the tail of
// a longer one: no letter or digit before it, and no digit then a separator.
func digitRunStarts(s string, i int) bool {
	b := at(s, i-1)
	if isAlnum(b) {
		return false
	}
	return b != '-' && b != '.' || !isDigit(at(s, i-2))
}

// digitRunEnds reports whether a number ending at i is not the head of a
// longer one: no letter or digit after it, and no separator from seps then a
// digit.
func digitRunEnds(s string, i int, seps string) bool {
	b := at(s, i)
	if isAlnum(b) {
		return false
	}
	return b == 0 || strings.IndexByte(seps, b) < 0 || !isDigit(at(s, i+1))
}

// countDigits counts the ASCII digits of s.
func countDigits(s string) int {
	n := 0
	for i := range len(s) {
		if isDigit(s[i]) {
			n++
		}
	}
	return n
}

// creditCards finds card numbers in the numeric span s[from:to]: 13 to 19
// digits in whole groups of a digit run, Luhn-valid, not one repeated digit,
// with an issuer prefix and a length that issuer uses. Groups glued to a
// letter never start or end a number, so the digits of an identifier are
// not read as a card.
func creditCards(c *collector, from, to, digits int) {
	s := c.s
	if digits < 13 {
		return
	}
	for i := from; i < to; {
		if !isDigit(s[i]) {
			i++
			continue
		}
		// A run of digits joined by single spaces or dashes.
		start, n := i, 0
	run:
		for i < to {
			switch {
			case isDigit(s[i]):
				n++
				i++
			case (s[i] == ' ' || s[i] == '-') && isDigit(at(s, i+1)):
				i++
			default:
				break run
			}
		}
		if n < 13 {
			continue
		}
		groups := splitGroups(s, start, i)
		first, last := 0, len(groups)-1
		if isAlnum(at(s, start-1)) {
			first++
		}
		if isAlnum(at(s, i)) {
			last--
		}
		for g := first; g <= last; {
			end := cardEnd(s, groups, g, last)
			if end < 0 {
				g++
				continue
			}
			c.add(piiCreditCard, "CREDIT_CARD", 1, groups[g][0], groups[end][1])
			g = end + 1
		}
	}
}

// splitGroups returns the [start, end) of each digit group in s[from:to].
func splitGroups(s string, from, to int) [][2]int {
	var groups [][2]int
	start := from
	for i := from; i < to; i++ {
		if !isDigit(s[i]) {
			groups = append(groups, [2]int{start, i})
			start = i + 1
		}
	}
	return append(groups, [2]int{start, to})
}

// cardEnd returns the last group of the longest valid card number that
// starts at group g and ends by group last, or -1.
func cardEnd(s string, groups [][2]int, g, last int) int {
	digits := make([]byte, 0, 24)
	type end struct{ group, digits int }
	ends := make([]end, 0, 19)
	for e := g; e <= last && len(digits) <= 19; e++ {
		digits = append(digits, s[groups[e][0]:groups[e][1]]...)
		if len(digits) >= 13 && len(digits) <= 19 {
			ends = append(ends, end{e, len(digits)})
		}
	}
	for k := len(ends) - 1; k >= 0; k-- {
		if validCard(digits[:ends[k].digits]) {
			return ends[k].group
		}
	}
	return -1
}

// issuerLength reports whether d starts like a card issuer's numbers and has
// a length that issuer uses: Visa 4 (13, 16, 19), Mastercard 51 to 55 and
// 2221 to 2720 (16), Amex 34 and 37 (15), Discover 6011, 644 to 649 and 65,
// UnionPay 62 and JCB 3528 to 3589 (16 to 19), Diners 300 to 305, 36, 38 and
// 39 (14 to 19). Decimal IDs such as trace IDs rarely fit.
func issuerLength(d []byte) bool {
	n := len(d)
	p2 := int(d[0]-'0')*10 + int(d[1]-'0')
	p3 := p2*10 + int(d[2]-'0')
	p4 := p3*10 + int(d[3]-'0')
	switch {
	case d[0] == '4':
		return n == 13 || n == 16 || n == 19
	case p2 >= 51 && p2 <= 55, p4 >= 2221 && p4 <= 2720:
		return n == 16
	case p2 == 34, p2 == 37:
		return n == 15
	case p4 == 6011, p3 >= 644 && p3 <= 649, p2 == 65, p2 == 62, p4 >= 3528 && p4 <= 3589:
		return n >= 16 && n <= 19
	case p3 >= 300 && p3 <= 305, p2 == 36, p2 == 38, p2 == 39:
		return n >= 14 && n <= 19
	}
	return false
}

// validCard checks a card number's issuer prefix and length, Luhn sum and
// that it is not one repeated digit.
func validCard(d []byte) bool {
	if !issuerLength(d) {
		return false
	}
	repeated := true
	sum := 0
	for i := range d {
		v := int(d[len(d)-1-i] - '0')
		if i%2 == 1 {
			v *= 2
			if v > 9 {
				v -= 9
			}
		}
		sum += v
		repeated = repeated && d[i] == d[0]
	}
	return sum%10 == 0 && !repeated
}

// ibanPattern is a country code, two check digits and up to 30 letters or
// digits, in groups of four with optional single spaces, anchored so it runs
// only where a candidate starts.
var ibanPattern = regexp.MustCompile(`^[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?`)

// ibans finds IBANs that pass the mod-97 check. Candidates start at two
// capitals and two digits that do not follow a letter or digit. A spaced
// IBAN may be followed by an upper-case word, so shorter whole-group
// prefixes are tried too.
func ibans(c *collector) {
	s := c.s
	for i := 0; i+4 <= len(s); i++ {
		if !isUpper(s[i]) || !isUpper(s[i+1]) || !isDigit(s[i+2]) || !isDigit(s[i+3]) || isAlnum(at(s, i-1)) {
			continue
		}
		loc := ibanPattern.FindStringIndex(s[i:min(len(s), i+42)])
		if loc == nil {
			continue
		}
		start, end := i, i+loc[1]
		for end > start {
			if !isAlnum(at(s, end)) && validIBAN(s[start:end]) {
				c.add(piiIBAN, "IBAN", 1, start, end)
				break
			}
			cut := strings.LastIndexByte(s[start:end], ' ')
			if cut < 0 {
				break
			}
			end = start + cut
		}
		i = start + loc[1] - 1
	}
}

// isUpper reports whether b is an ASCII capital.
func isUpper(b byte) bool {
	return b >= 'A' && b <= 'Z'
}

// validIBAN checks the length and mod-97 checksum of an IBAN, ignoring
// spaces.
func validIBAN(v string) bool {
	compact := strings.ReplaceAll(v, " ", "")
	if len(compact) < 15 || len(compact) > 34 {
		return false
	}
	rearranged := compact[4:] + compact[:4]
	rem := 0
	for i := range len(rearranged) {
		ch := rearranged[i]
		if isDigit(ch) {
			rem = (rem*10 + int(ch-'0')) % 97
		} else {
			rem = (rem*100 + int(ch-'A'+10)) % 97
		}
	}
	return rem == 1
}

// ipv4 finds IPv4 addresses in the numeric span s[from:to]: four dotted
// numbers of 0 to 255 without leading zeros, not part of a longer dotted
// number.
func ipv4(c *collector, from, to, _ int) {
	s := c.s
	if strings.Count(s[from:to], ".") < 3 {
		return
	}
	for i := from; i < to; i++ {
		if !isDigit(s[i]) || isAlnum(at(s, i-1)) || at(s, i-1) == '.' {
			continue
		}
		end := ipv4End(s, i)
		if end < 0 {
			continue
		}
		if b := at(s, end); isAlnum(b) || b == '.' && isDigit(at(s, end+1)) {
			continue
		}
		c.add(piiIPAddress, "IP_ADDRESS", 1, i, end)
		i = end - 1
	}
}

// ipv4End returns the end of the dotted quad starting at i, or -1.
func ipv4End(s string, i int) int {
	for part := range 4 {
		if part > 0 {
			if at(s, i) != '.' {
				return -1
			}
			i++
		}
		j, v := i, 0
		for j < len(s) && j-i < 3 && isDigit(s[j]) {
			v = v*10 + int(s[j]-'0')
			j++
		}
		if j == i || isDigit(at(s, j)) || v > 255 || j-i > 1 && s[i] == '0' {
			return -1
		}
		i = j
	}
	return i
}

// ipv6 finds IPv6 addresses: runs of hex digits, ':' and '.' of up to 45
// bytes holding two or more colons, not glued to a letter or digit, that
// netip accepts.
func ipv6(c *collector) {
	s := c.s
	for from := 0; from < len(s); {
		k := strings.IndexByte(s[from:], ':')
		if k < 0 {
			return
		}
		k += from
		start, end := k, k
		for start > from && isIPv6Byte(s[start-1]) {
			start--
		}
		for end < len(s) && isIPv6Byte(s[end]) {
			end++
		}
		from = end
		for end > k && s[end-1] == '.' {
			end--
		}
		v := s[start:end]
		if len(v) < 3 || len(v) > 45 || strings.Count(v, ":") < 2 || isAlnum(at(s, start-1)) || isAlnum(at(s, end)) {
			continue
		}
		if addr, err := netip.ParseAddr(v); err != nil || !addr.Is6() {
			continue
		}
		c.add(piiIPAddress, "IP_ADDRESS", 1, start, end)
	}
}

// isIPv6Byte reports whether b may appear in an IPv6 address.
func isIPv6Byte(b byte) bool {
	return isDigit(b) || b >= 'a' && b <= 'f' || b >= 'A' && b <= 'F' || b == ':' || b == '.'
}
