package codes

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"strings"
)

// Alphabet omits I, L, O and U to reduce transcription mistakes and accidental words.
const alphabet = "23456789ABCDEFGHJKMNPQRSTVWXYZ"

func Generate() (string, error) {
	raw := make([]byte, 8)
	for i := range raw {
		var sample [1]byte
		for {
			if _, err := rand.Read(sample[:]); err != nil {
				return "", fmt.Errorf("random code: %w", err)
			}
			// Rejection sampling avoids modulo bias for a 32-character alphabet.
			if int(sample[0]) < 256-(256%len(alphabet)) {
				raw[i] = alphabet[int(sample[0])%len(alphabet)]
				break
			}
		}
	}
	return string(raw[:4]) + "-" + string(raw[4:]), nil
}

func Normalize(code string) string {
	replacer := strings.NewReplacer("-", "", " ", "", "\t", "", "\n", "", "\r", "")
	return strings.ToUpper(replacer.Replace(strings.TrimSpace(code)))
}

func Valid(code string) bool {
	code = Normalize(code)
	if len(code) != 8 {
		return false
	}
	for _, char := range code {
		if !strings.ContainsRune(alphabet, char) {
			return false
		}
	}
	return true
}

func HMAC(key []byte, code string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(Normalize(code)))
	return mac.Sum(nil)
}
