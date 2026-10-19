package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestGeneratedRegionPreservesSourceAndCheckoutNewlines(t *testing.T) {
	for _, newline := range []string{"\n", "\r\n"} {
		t.Run(strings.ReplaceAll(newline, "\r", "CR"), func(t *testing.T) {
			before, after := "// unrelated ß\r\n", "\n// caller code remains\r\n"
			source := []byte(before + begin + newline + "stale" + newline + end + after)
			original := append([]byte{}, source...)
			replacement := begin + "\ncurrent\n" + end
			result, stale, err := updateRegion(source, replacement)
			if err != nil || !stale || !bytes.Equal(source, original) {
				t.Fatal("generation must replace a stale region without mutating the input", err)
			}
			if want := before + strings.ReplaceAll(replacement, "\n", newline) + after; string(result) != want {
				t.Fatal("generation changed unrelated source or checkout newline style")
			}
			unchanged, stale, err := updateRegion(result, replacement)
			if err != nil || stale || !bytes.Equal(unchanged, result) {
				t.Fatal("the generated check must be idempotent for LF and CRLF", err)
			}
		})
	}
}

func TestGeneratedRegionRejectsMissingOrAmbiguousMarkers(t *testing.T) {
	for _, value := range []string{"", begin, end + begin, begin + end + end, begin + begin + end} {
		source := []byte(value)
		original := append([]byte{}, source...)
		if result, _, err := updateRegion(source, begin+"\ncurrent\n"+end); err == nil || result != nil {
			t.Fatal("missing or ambiguous generated markers must fail")
		}
		if !bytes.Equal(source, original) {
			t.Fatal("a rejected region changed its source")
		}
	}
}

func TestCompressedCaseTableMatchesEveryGoScalar(t *testing.T) {
	// ranges validates every code point against unicode.ToUpper before it can
	// render any platform source, including identity values and stride gaps.
	table, changed := ranges()
	if len(table) == 0 || changed == 0 {
		t.Fatal("the pinned Unicode case mapping is empty")
	}
}
