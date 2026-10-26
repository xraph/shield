package perception

import (
	"math"
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
