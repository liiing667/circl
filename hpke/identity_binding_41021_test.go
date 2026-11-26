package hpke_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
)

type uid41021XKEM struct {
	id     hpke.KEM
	scheme kem.Scheme
	pk     kem.PublicKey
	sk     kem.PrivateKey
}

func uid41021ReconstructXKEM(t *testing.T, id hpke.KEM) uid41021XKEM {
	t.Helper()

	scheme := id.Scheme()
	pk, sk, err := scheme.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Serialization is the in-process equivalent of handing the keys to
	// another process and reconstructing them from their public encodings.
	pkData, err := pk.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	skData, err := sk.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	pk, err = scheme.UnmarshalBinaryPublicKey(pkData)
	if err != nil {
		t.Fatal(err)
	}
	sk, err = scheme.UnmarshalBinaryPrivateKey(skData)
	if err != nil {
		t.Fatal(err)
	}
	if pk.Scheme().Name() != scheme.Name() || sk.Scheme().Name() != scheme.Name() {
		t.Fatal("reconstructed XKEM key changed scheme identity")
	}

	return uid41021XKEM{id: id, scheme: scheme, pk: pk, sk: sk}
}

func TestUID41021XKEMRejectsOtherCurve(t *testing.T) {
	ids := []hpke.KEM{
		hpke.KEM_X25519_HKDF_SHA256,
		hpke.KEM_X448_HKDF_SHA512,
	}
	keys := make([]uid41021XKEM, len(ids))
	for i, id := range ids {
		keys[i] = uid41021ReconstructXKEM(t, id)
	}

	kdf := hpke.KDF_HKDF_SHA256
	aead := hpke.AEAD_AES128GCM

	for i, key := range keys {
		other := keys[1-i]
		t.Run(key.scheme.Name(), func(t *testing.T) {
			seed := make([]byte, key.scheme.EncapsulationSeedSize())
			if _, _, err := key.scheme.EncapsulateDeterministically(other.pk, seed); err == nil {
				t.Fatal("encapsulation accepted a key from another XKEM curve")
			}

			ct, _, err := key.scheme.Encapsulate(key.pk)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := key.scheme.Decapsulate(key.sk, ct); err != nil {
				t.Fatalf("matching private key failed: %v", err)
			}
			if _, err := key.scheme.Decapsulate(other.sk, ct); err == nil {
				t.Fatal("decapsulation accepted a key from another XKEM curve")
			}

			suite := hpke.NewSuite(key.id, kdf, aead)

			sender, err := suite.NewSender(other.pk, nil)
			if err == nil {
				if _, _, err := sender.Setup(rand.Reader); err == nil {
					t.Fatal("HPKE sender accepted a public key from another XKEM curve")
				}
			}

			enc, sealer, err := func() ([]byte, hpke.Sealer, error) {
				sender, err := suite.NewSender(key.pk, nil)
				if err != nil {
					return nil, nil, err
				}
				return sender.Setup(rand.Reader)
			}()
			if err != nil {
				t.Fatal(err)
			}

			receiver, err := suite.NewReceiver(other.sk, nil)
			if err == nil {
				if _, err := receiver.Setup(enc); err == nil {
					t.Fatal("HPKE receiver accepted a private key from another XKEM curve")
				}
			}

			receiver, err = suite.NewReceiver(key.sk, nil)
			if err != nil {
				t.Fatal(err)
			}
			opener, err := receiver.Setup(enc)
			if err != nil {
				t.Fatalf("matching HPKE receiver setup failed: %v", err)
			}

			plaintext := []byte("ordinary ciphertext")
			ciphertext, err := sealer.Seal(plaintext, nil)
			if err != nil {
				t.Fatal(err)
			}
			got, err := opener.Open(ciphertext, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Fatal("HPKE round trip changed plaintext")
			}
		})
	}
}
