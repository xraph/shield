package scan

import "strings"

// QuoteTag is the element Quote wraps untrusted text in.
const QuoteTag = "untrusted_content"

// closingTag is the start of the tag that would end the wrapper early.
const closingTag = "</" + QuoteTag

// Quote wraps untrusted text so a model reads it as data, not as
// instructions:
//
//	<untrusted_content source="S">
//	text
//	</untrusted_content>
//
// Every closing tag inside text, in any letter case, has its slash escaped
// ("<\/untrusted_content"), so the only closing tag is the last line. S is
// source in lower case with every rune other than a to z, 0 to 9, '_', '.'
// and '-' replaced by '_'; an empty source is "unknown".
func Quote(source, text string) string {
	var b strings.Builder
	b.Grow(len(text) + len(source) + 2*len(QuoteTag) + 24)
	b.WriteString("<" + QuoteTag + ` source="`)
	b.WriteString(quoteSource(source))
	b.WriteString("\">\n")
	writeEscaped(&b, text)
	b.WriteString("\n" + closingTag + ">")
	return b.String()
}

// quoteSource sanitizes a source name for the wrapper's attribute.
func quoteSource(source string) string {
	if source == "" {
		return "unknown"
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_', r == '.', r == '-':
			return r
		}
		return '_'
	}, strings.ToLower(source))
}

// writeEscaped writes text with the slash of every closing tag escaped. The
// match ignores ASCII case and keeps the original letters.
func writeEscaped(b *strings.Builder, text string) {
	for {
		i := indexFold(text, closingTag)
		if i < 0 {
			b.WriteString(text)
			return
		}
		b.WriteString(text[:i])
		b.WriteString(`<\/`)
		b.WriteString(text[i+2 : i+len(closingTag)])
		text = text[i+len(closingTag):]
	}
}

// indexFold is strings.Index ignoring ASCII case. needle is lower case.
func indexFold(s, needle string) int {
	for i := 0; i+len(needle) <= len(s); i++ {
		j := 0
		for j < len(needle) && lowerASCII(s[i+j]) == needle[j] {
			j++
		}
		if j == len(needle) {
			return i
		}
	}
	return -1
}

func lowerASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}
