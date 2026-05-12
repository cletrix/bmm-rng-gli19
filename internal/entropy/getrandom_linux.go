//go:build linux

package entropy

import "syscall"

// readEntropy fills b via getrandom(2) with flags=0.
// Blocks until the kernel has sufficient entropy; never falls back to /dev/urandom.
// Retries automatically on EINTR.
func readEntropy(b []byte) error {
	for len(b) > 0 {
		n, err := syscall.Getrandom(b, 0)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}
