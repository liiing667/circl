package slhdsa_test

import (
	"crypto"
	"math"
	"testing"

	"github.com/cloudflare/circl/sign/slhdsa"
)

func TestIssue41003PreHashIdentifierBoundary(t *testing.T) {
	for _, h := range []crypto.Hash{
		crypto.Hash(math.MaxUint),
		crypto.Hash(math.MaxUint32),
		crypto.Hash(255),
	} {
		ph, err := slhdsa.NewPreHashWithHash(h)
		if err == nil {
			t.Fatalf("hash %d: expected error", h)
		}
		if ph != nil {
			t.Fatalf("hash %d: returned non-nil PreHash", h)
		}
	}

	ph, err := slhdsa.NewPreHashWithHash(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ph.Write([]byte("standard prehash continues to work")); err != nil {
		t.Fatal(err)
	}
	if _, err := ph.BuildMessage(); err != nil {
		t.Fatal(err)
	}
}
