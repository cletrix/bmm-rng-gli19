//go:build !linux

package entropy

import "crypto/rand"

// readEntropy fills b using crypto/rand (non-Linux development fallback).
// Production must run on Linux where getrandom(2) is used directly.
func readEntropy(b []byte) error {
	_, err := rand.Read(b)
	return err
}
