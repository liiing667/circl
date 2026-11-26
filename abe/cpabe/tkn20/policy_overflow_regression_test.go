package tkn20

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"
)

// TestEncryptRejectsOversizedPolicy guards the uint16 length-prefix
// wraparound: an oversized policy must be rejected by Encrypt rather than
// producing a ciphertext that cannot be recovered by a legitimate key.
func TestEncryptRejectsOversizedPolicy(t *testing.T) {
	const label = "contributor_email_address"
	const n = 700

	clauses := make([]string, n)
	for i := range n {
		v := fmt.Sprintf(
			"%08d_%s_%s_%s",
			10_000_000+i,
			[]string{"billowy", "righteous", "abstracted", "statuesque"}[i%4],
			[]string{"pupil", "newsletter", "puppy", "stormy"}[(i/3)%4],
			[]string{"reaction", "rabbit", "argument", "reading"}[(i/7)%4],
		)
		clauses[i] = label + ":" + v
	}

	var policy Policy
	if err := policy.FromString(strings.Join(clauses, " or ")); err != nil {
		t.Fatalf("parse large policy: %v", err)
	}

	pk, _, err := Setup(rand.Reader)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	ct, err := pk.Encrypt(rand.Reader, policy, []byte("large policy plaintext"))
	if err == nil {
		t.Fatalf("expected oversized policy encryption to fail, got %d-byte ciphertext", len(ct))
	}
	if ct != nil {
		t.Fatalf("failed encryption returned %d bytes", len(ct))
	}
}

// TestDecryptFailureReturnsNoPlaintext checks the caller-visible
// contract needed by a batch consumer: a failed item returns an error and a
// nil plaintext, while a retry/independent consumer can still recover the
// valid item.
func TestDecryptFailureReturnsNoPlaintext(t *testing.T) {
	policyStr := "(country: US) and (role: admin)"

	var policy Policy
	if err := policy.FromString(policyStr); err != nil {
		t.Fatalf("policy: %v", err)
	}

	pk, msk, err := Setup(rand.Reader)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	rightAttrs := Attributes{}
	rightAttrs.FromMap(map[string]string{"country": "US", "role": "admin"})
	key, err := msk.KeyGen(rand.Reader, rightAttrs)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	want := []byte("batch item two")
	ct, err := pk.Encrypt(rand.Reader, policy, want)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	tampered := bytes.Clone(ct)
	tampered[len(tampered)-1] ^= 0x01

	got, err := key.Decrypt(tampered)
	if err == nil {
		t.Fatal("expected tampered batch item to fail")
	}
	if got != nil {
		t.Fatalf("failed decryption returned plaintext %q", got)
	}

	got, err = key.Decrypt(ct)
	if err != nil {
		t.Fatalf("valid retry failed: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("retry plaintext = %q, want %q", got, want)
	}
}
