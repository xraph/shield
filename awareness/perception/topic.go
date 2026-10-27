package perception

import (
	"regexp"

	"github.com/xraph/shield/internal/textnorm"
)

// Topic reports whether any pattern matches text, as given or in its folded
// form (see textnorm.Fold: lower case, NFKC, invisible runes removed), so a
// lower-case pattern still sees "RELEASE" and a word split by a zero-width
// space. Nil patterns are skipped.
func Topic(text string, patterns []*regexp.Regexp) bool {
	folded, haveFolded := "", false
	for _, re := range patterns {
		if re == nil {
			continue
		}
		if re.MatchString(text) {
			return true
		}
		if !haveFolded {
			folded, haveFolded = textnorm.Fold(text).Folded, true
		}
		if folded != text && re.MatchString(folded) {
			return true
		}
	}
	return false
}
