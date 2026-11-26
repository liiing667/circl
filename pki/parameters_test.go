package pki_test

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"github.com/cloudflare/circl/pki"
	"github.com/cloudflare/circl/sign/ed25519"
)

var issue40999ASN1Null = asn1.RawValue{FullBytes: []byte{0x05, 0x00}}

func TestIssue40999RejectPKIXPublicKeyParameters(t *testing.T) {
	pk, _, err := ed25519.Scheme().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	der, err := pki.MarshalPKIXPublicKey(pk)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pki.UnmarshalPKIXPublicKey(der); err != nil {
		t.Fatalf("standard public key rejected: %v", err)
	}

	var parsed struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &parsed); err != nil {
		t.Fatal(err)
	}
	parsed.Algorithm.Parameters = issue40999ASN1Null
	bad, err := asn1.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pki.UnmarshalPKIXPublicKey(bad); err == nil {
		t.Fatal("public key with algorithm parameters accepted")
	}
}

func TestIssue40999RejectPKIXPrivateKeyParameters(t *testing.T) {
	_, sk, err := ed25519.Scheme().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	der, err := pki.MarshalPKIXPrivateKey(sk)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pki.UnmarshalPKIXPrivateKey(der); err != nil {
		t.Fatalf("standard private key rejected: %v", err)
	}

	var parsed struct {
		Version    int
		Algorithm  pkix.AlgorithmIdentifier
		PrivateKey []byte
	}
	if _, err := asn1.Unmarshal(der, &parsed); err != nil {
		t.Fatal(err)
	}
	parsed.Algorithm.Parameters = issue40999ASN1Null
	bad, err := asn1.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pki.UnmarshalPKIXPrivateKey(bad); err == nil {
		t.Fatal("private key with algorithm parameters accepted")
	}
}
