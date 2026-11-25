package hpke_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem/xwing"
)

var issue41003KEMs = []hpke.KEM{
	hpke.KEM_P256_HKDF_SHA256,
	hpke.KEM_P384_HKDF_SHA384,
	hpke.KEM_P521_HKDF_SHA512,
	hpke.KEM_X25519_HKDF_SHA256,
	hpke.KEM_X448_HKDF_SHA512,
	hpke.KEM_X25519_KYBER768_DRAFT00,
	hpke.KEM_XWING,
}

func TestIssue41003EmptyBuffers(t *testing.T) {
	if _, err := hpke.UnmarshalSealer(nil); err == nil {
		t.Fatal("empty sealer buffer accepted")
	}
	if _, err := hpke.UnmarshalOpener([]byte{}); err == nil {
		t.Fatal("empty opener buffer accepted")
	}

	for _, id := range issue41003KEMs {
		t.Run(id.Scheme().Name(), func(t *testing.T) {
			scheme := id.Scheme()
			pk, sk, err := scheme.GenerateKeyPair()
			if err != nil {
				t.Fatal(err)
			}

			if _, err := scheme.UnmarshalBinaryPublicKey(nil); err == nil {
				t.Fatal("empty public key buffer accepted")
			}
			if _, err := scheme.UnmarshalBinaryPrivateKey(nil); err == nil {
				t.Fatal("empty private key buffer accepted")
			}
			if _, _, err := scheme.EncapsulateDeterministically(pk, nil); err == nil {
				t.Fatal("empty encapsulation seed accepted")
			}
			if _, err := scheme.Decapsulate(sk, nil); err == nil {
				t.Fatal("empty ciphertext buffer accepted")
			}

			seed := make([]byte, scheme.EncapsulationSeedSize())
			ct, ss, err := scheme.EncapsulateDeterministically(pk, seed)
			if err != nil {
				t.Fatalf("full seed rejected: %v", err)
			}
			got, err := scheme.Decapsulate(sk, ct)
			if err != nil {
				t.Fatalf("full ciphertext rejected: %v", err)
			}
			if !bytes.Equal(ss, got) {
				t.Fatal("shared secrets do not match")
			}
		})
	}
}

func TestIssue41003ReceiverBindsKEMIdentity(t *testing.T) {
	for _, id := range issue41003KEMs {
		suite := hpke.NewSuite(id, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
		pk, sk, err := id.Scheme().GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}

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
		if _, err := opener.Open(mustSealIssue41003(t, sealer), nil); err != nil {
			t.Fatal(err)
		}

		seed := make([]byte, id.Scheme().EncapsulationSeedSize())
		ct, _, err := id.Scheme().EncapsulateDeterministically(pk, seed)
		if err != nil {
			t.Fatal(err)
		}

		for _, other := range issue41003KEMs {
			if other == id {
				continue
			}
			opk, osk, err := other.Scheme().GenerateKeyPair()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := suite.NewSender(opk, nil); err == nil {
				t.Fatalf("%s sender accepted %s key", id.Scheme().Name(), other.Scheme().Name())
			}
			if _, err := suite.NewReceiver(osk, nil); err == nil {
				t.Fatalf("%s receiver accepted %s key", id.Scheme().Name(), other.Scheme().Name())
			}
			if _, _, err := id.Scheme().EncapsulateDeterministically(opk, seed); err == nil {
				t.Fatalf("%s scheme encapsulated to %s key", id.Scheme().Name(), other.Scheme().Name())
			}
			if _, err := id.Scheme().Decapsulate(osk, ct); err == nil {
				t.Fatalf("%s scheme decapsulated with %s key", id.Scheme().Name(), other.Scheme().Name())
			}
		}
	}
}

func TestIssue41003AcceptsNativeXWingIdentity(t *testing.T) {
	pk, sk, err := xwing.Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	suite := hpke.NewSuite(hpke.KEM_XWING, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
	sender, err := suite.NewSender(pk, nil)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := suite.NewReceiver(sk, nil)
	if err != nil {
		t.Fatal(err)
	}
	enc, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	opener, err := receiver.Setup(enc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := opener.Open(mustSealIssue41003(t, sealer), nil); err != nil {
		t.Fatal(err)
	}
}

func mustSealIssue41003(t *testing.T, sealer hpke.Sealer) []byte {
	t.Helper()
	ct, err := sealer.Seal([]byte("ok"), nil)
	if err != nil {
		t.Fatal(err)
	}
	return ct
}
