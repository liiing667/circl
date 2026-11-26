package pki_test

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"github.com/cloudflare/circl/pki"
	"github.com/cloudflare/circl/sign/ed25519"
)

var uid41021ASN1Null = asn1.RawValue{FullBytes: []byte{0x05, 0x00}}

func TestUID41021RejectPublicKeyAlgorithmParameters(t *testing.T) {
	pk, _, err := ed25519.Scheme().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	der, err := pki.MarshalPKIXPublicKey(pk)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pki.UnmarshalPKIXPublicKey(der); err != nil {
		t.Fatalf("parameterless public key was rejected: %v", err)
	}

	var parsed struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &parsed); err != nil {
		t.Fatal(err)
	}
	parsed.Algorithm.Parameters = uid41021ASN1Null
	bad, err := asn1.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pki.UnmarshalPKIXPublicKey(bad); err == nil {
		t.Fatal("public key with algorithm parameters was accepted")
	}
}

func TestUID41021RejectPrivateKeyAlgorithmParameters(t *testing.T) {
	_, sk, err := ed25519.Scheme().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	der, err := pki.MarshalPKIXPrivateKey(sk)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pki.UnmarshalPKIXPrivateKey(der); err != nil {
		t.Fatalf("parameterless private key was rejected: %v", err)
	}

	var parsed struct {
		Version    int
		Algorithm  pkix.AlgorithmIdentifier
		PrivateKey []byte
	}
	if _, err := asn1.Unmarshal(der, &parsed); err != nil {
		t.Fatal(err)
	}
	parsed.Algorithm.Parameters = uid41021ASN1Null
	bad, err := asn1.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pki.UnmarshalPKIXPrivateKey(bad); err == nil {
		t.Fatal("private key with algorithm parameters was accepted")
	}
}
