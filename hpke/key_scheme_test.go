package hpke_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/xwing"
)

var issue40999KEMs = []hpke.KEM{
	hpke.KEM_P256_HKDF_SHA256,
	hpke.KEM_P384_HKDF_SHA384,
	hpke.KEM_P521_HKDF_SHA512,
	hpke.KEM_X25519_HKDF_SHA256,
	hpke.KEM_X448_HKDF_SHA512,
	hpke.KEM_X25519_KYBER768_DRAFT00,
	hpke.KEM_XWING,
}

func issue40999KeyPair(t *testing.T, id hpke.KEM) (kem.PublicKey, kem.PrivateKey) {
	t.Helper()
	pk, sk, err := id.Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return pk, sk
}

func TestIssue40999KeysBelongToSuiteKEM(t *testing.T) {
	kdfID := hpke.KDF_HKDF_SHA256
	aeadID := hpke.AEAD_AES128GCM

	for _, id := range issue40999KEMs {
		t.Run(id.Scheme().Name(), func(t *testing.T) {
			suite := hpke.NewSuite(id, kdfID, aeadID)
			pk, sk := issue40999KeyPair(t, id)
			sender, err := suite.NewSender(pk, nil)
			if err != nil {
				t.Fatalf("matching public key rejected: %v", err)
			}
			receiver, err := suite.NewReceiver(sk, nil)
			if err != nil {
				t.Fatalf("matching private key rejected: %v", err)
			}

			enc, sealer, err := sender.Setup(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			opener, err := receiver.Setup(enc)
			if err != nil {
				t.Fatal(err)
			}
			ct, err := sealer.Seal([]byte("message"), nil)
			if err != nil {
				t.Fatal(err)
			}
			pt, err := opener.Open(ct, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(pt, []byte("message")) {
				t.Fatal("round trip failed")
			}

			seed := make([]byte, id.Scheme().EncapsulationSeedSize())
			ct2, ss, err := id.Scheme().EncapsulateDeterministically(pk, seed)
			if err != nil {
				t.Fatal(err)
			}
			ss2, err := id.Scheme().Decapsulate(sk, ct2)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(ss, ss2) {
				t.Fatal("shared secrets do not match")
			}

			for _, other := range issue40999KEMs {
				if other == id {
					continue
				}
				opk, osk := issue40999KeyPair(t, other)

				if _, err := suite.NewSender(opk, nil); err == nil {
					t.Fatalf("%s sender accepted a %s public key",
						id.Scheme().Name(), other.Scheme().Name())
				}
				if _, err := suite.NewReceiver(osk, nil); err == nil {
					t.Fatalf("%s receiver accepted a %s private key",
						id.Scheme().Name(), other.Scheme().Name())
				}
				if _, _, err := id.Scheme().EncapsulateDeterministically(opk, seed); err == nil {
					t.Fatalf("%s encapsulated to a %s public key",
						id.Scheme().Name(), other.Scheme().Name())
				}
				if _, err := id.Scheme().Decapsulate(osk, ct2); err == nil {
					t.Fatalf("%s decapsulated with a %s private key",
						id.Scheme().Name(), other.Scheme().Name())
				}
			}
		})
	}
}

func TestIssue40999AuthKeysBelongToSuiteKEM(t *testing.T) {
	suite := hpke.NewSuite(
		hpke.KEM_X25519_HKDF_SHA256,
		hpke.KDF_HKDF_SHA256,
		hpke.AEAD_AES128GCM,
	)
	pkR, skR := issue40999KeyPair(t, hpke.KEM_X25519_HKDF_SHA256)
	_, otherSk := issue40999KeyPair(t, hpke.KEM_X448_HKDF_SHA512)
	otherPk, _ := issue40999KeyPair(t, hpke.KEM_X448_HKDF_SHA512)

	sender, err := suite.NewSender(pkR, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := sender.SetupAuth(rand.Reader, otherSk); err == nil {
		t.Fatal("sender accepted a foreign authentication private key")
	}
	if _, _, err := sender.SetupAuthPSK(rand.Reader, otherSk, []byte("psk"), []byte("id")); err == nil {
		t.Fatal("sender accepted a foreign authentication private key in PSK mode")
	}

	receiver, err := suite.NewReceiver(skR, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := receiver.SetupAuth(nil, otherPk); err == nil {
		t.Fatal("receiver accepted a foreign authentication public key")
	}
	if _, err := receiver.SetupAuthPSK(nil, []byte("psk"), []byte("id"), otherPk); err == nil {
		t.Fatal("receiver accepted a foreign authentication public key in PSK mode")
	}
}

func TestIssue40999XWingNativeKeysAccepted(t *testing.T) {
	pk, sk, err := xwing.Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	suite := hpke.NewSuite(
		hpke.KEM_XWING,
		hpke.KDF_HKDF_SHA256,
		hpke.AEAD_AES128GCM,
	)
	sender, err := suite.NewSender(pk, nil)
	if err != nil {
		t.Fatalf("native X-Wing public key rejected: %v", err)
	}
	receiver, err := suite.NewReceiver(sk, nil)
	if err != nil {
		t.Fatalf("native X-Wing private key rejected: %v", err)
	}
	enc, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	opener, err := receiver.Setup(enc)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := sealer.Seal([]byte("message"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := opener.Open(ct, nil); err != nil {
		t.Fatal(err)
	}
}
