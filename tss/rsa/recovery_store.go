package rsa

import (
	"crypto/rsa"
	"os"
	"path/filepath"
)

// SaveRecoveryFile atomically writes recovery state to path with owner-only
// permissions. The state contains signature shares, not the long-term key
// share, but should still be treated as sensitive transaction material.
func SaveRecoveryFile(path string, recovery *Recovery) error {
	data, err := recovery.MarshalBinary()
	if err != nil {
		return err
	}

	// The path is supplied by the trusted threshold service configuration;
	// this helper intentionally manages operator-local recovery state.
	// #nosec G304 -- path is an explicit state-file argument, not request input.
	file, err := os.CreateTemp(filepath.Dir(path), ".circl-recovery-*")
	if err != nil {
		return err
	}
	tmpPath := file.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}

	cleanup = false
	return nil
}

// OpenRecoveryFile reads and validates durable recovery state for
// expectedTransactionID. The trusted RSA public key is supplied by the caller.
func OpenRecoveryFile(path string, pub *rsa.PublicKey, expectedTransactionID []byte) (*Recovery, error) {
	// #nosec G304 -- path is an explicit state-file argument from trusted config.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return OpenRecovery(pub, expectedTransactionID, data)
}
