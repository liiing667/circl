package rsa

import (
	"encoding/binary"
	"math"
	"strings"
	"testing"
)

func TestIssue41001CombineEmptyShares(t *testing.T) {
	// A nil public key is intentional: share-set validation must fail before
	// the modulus is touched.
	for _, shares := range [][]SignShare{nil, {}} {
		sig, err := CombineSignShares(nil, 3, 2, shares, []byte("digest"))
		if err == nil {
			t.Fatalf("CombineSignShares(%d shares) succeeded with sig %x", len(shares), sig)
		}
		if !strings.Contains(err.Error(), "no shares") {
			t.Fatalf("expected no-shares error, got %v", err)
		}
	}
}

func TestIssue41001UnmarshalLengthWraparound(t *testing.T) {
	lengths := []uint16{math.MaxUint16 - 7, math.MaxUint16 - 1, math.MaxUint16}

	for _, length := range lengths {
		keyData := make([]byte, 8+int(length))
		binary.BigEndian.PutUint16(keyData[6:8], length)
		keyData[8] = 1

		var keyShare KeyShare
		if err := keyShare.UnmarshalBinary(keyData); err == nil {
			t.Fatalf("KeyShare accepted truncated encoding with length %d", length)
		}

		signData := make([]byte, 8+int(length))
		binary.BigEndian.PutUint16(signData[6:8], length)
		signData[8] = 1

		var signShare SignShare
		if err := signShare.UnmarshalBinary(signData); err != nil {
			t.Fatalf("SignShare rejected in-bounds encoding with length %d: %v", length, err)
		}
	}
}
