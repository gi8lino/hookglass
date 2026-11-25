package verification

import (
	"crypto/sha256"
	"crypto/subtle"
)

// matchesDigest compares a value against an expected SHA-256 digest in constant time.
func matchesDigest(value string, expected [sha256.Size]byte) bool {
	provided := sha256.Sum256([]byte(value))

	return subtle.ConstantTimeCompare(provided[:], expected[:]) == 1
}
