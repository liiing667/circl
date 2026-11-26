package hpke_test

import (
	"testing"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/kem"
)

// TestXKEMRejectsForeignSchemeKeys ensures that foreign KEM keys fail
// closed instead of being truncated, zero-padded, or panicking in calcDH.
func TestXKEMRejectsForeignSchemeKeys(t *testing.T) {
	dhKEMs := []hpke.KEM{
		hpke.KEM_P256_HKDF_SHA256,
		hpke.KEM_P384_HKDF_SHA384,
		hpke.KEM_P521_HKDF_SHA512,
		hpke.KEM_X25519_HKDF_SHA256,
		hpke.KEM_X448_HKDF_SHA512,
	}

	for _, idA := range dhKEMs {
		for _, idB := range dhKEMs {
			if idA == idB {
				continue
			}
			checkXKEMWrongSchemeKeys(t, idA, idB)
		}
	}
}

func checkXKEMWrongSchemeKeys(t *testing.T, idA, idB hpke.KEM) {
	t.Helper()

	schemeA, pkA, skA := genKeyPair(t, idA)
	schemeB, pkB, skB := genKeyPair(t, idB)
	authA, ok := schemeA.(kem.AuthScheme)
	if !ok {
		t.Fatalf("%s does not support authenticated KEM", schemeA.Name())
	}

	t.Run(schemeA.Name()+"/"+schemeB.Name(), func(t *testing.T) {
		ct, _, err := schemeA.Encapsulate(pkA)
		test.CheckNoErr(t, err, "encapsulate")

		_, _, err = schemeA.Encapsulate(pkB)
		test.CheckIsErr(t, err, "encapsulation to a foreign public key must fail")

		_, err = schemeA.Decapsulate(skB, ct)
		test.CheckIsErr(t, err, "decapsulation with a foreign private key must fail")

		_, _, err = authA.AuthEncapsulate(pkA, skB)
		test.CheckIsErr(t, err, "auth encapsulation with a foreign private key must fail")

		_, err = authA.AuthDecapsulate(skA, ct, pkB)
		test.CheckIsErr(t, err, "auth decapsulation with a foreign public key must fail")

		// The matching keys must continue to complete the ordinary flow.
		ss, err := schemeA.Decapsulate(skA, ct)
		test.CheckNoErr(t, err, "decapsulate with the correct private key")
		if len(ss) == 0 {
			t.Fatal("empty shared secret after valid decapsulation")
		}
	})
}
