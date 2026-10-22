package codes

import (
	"bytes"
	"testing"
)

func TestGenerateNormalizeAndHMAC(t *testing.T) {
	first, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	second, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if !Valid(first) || Normalize(first) == Normalize(second) {
		t.Fatalf("unexpected generated codes %q and %q", first, second)
	}
	key := bytes.Repeat([]byte{7}, 32)
	if !bytes.Equal(HMAC(key, first), HMAC(key, Normalize(first))) {
		t.Fatal("formatting must not affect code HMAC")
	}
	if bytes.Equal(HMAC(key, first), []byte(Normalize(first))) {
		t.Fatal("HMAC must not reveal plaintext code")
	}
}

func TestRejectsAmbiguousOrMalformedCodes(t *testing.T) {
	for _, value := range []string{"", "123", "IIII-OOOO", "ABCD-EFG!"} {
		if Valid(value) {
			t.Fatalf("Valid(%q) = true", value)
		}
	}
}
