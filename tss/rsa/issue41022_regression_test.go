package rsa

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"path/filepath"
	"sync"
	"testing"
)

func newRecoveryTestFixture(t *testing.T) (*rsa.PrivateKey, []KeyShare, []byte, []SignShare) {
	t.Helper()

	const players = 3
	const threshold = 2

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	keyShares, err := Deal(rand.Reader, players, threshold, key, false)
	if err != nil {
		t.Fatalf("Deal: %v", err)
	}

	message := []byte("transaction-41022")
	digest, err := PadHash(PKCS1v15Padder{}, crypto.SHA256, &key.PublicKey, message)
	if err != nil {
		t.Fatalf("PadHash: %v", err)
	}

	signShares := make([]SignShare, threshold)
	for i := range threshold {
		signShares[i], err = keyShares[i].Sign(rand.Reader, &key.PublicKey, digest, true)
		if err != nil {
			t.Fatalf("Sign share %d: %v", i, err)
		}
	}

	return key, keyShares, digest, signShares
}

func TestCombineSignSharesRejectsIncompleteUniqueSet(t *testing.T) {
	key, _, digest, signShares := newRecoveryTestFixture(t)

	tests := []struct {
		name   string
		shares []SignShare
	}{
		{name: "duplicate index", shares: []SignShare{signShares[0], signShares[0]}},
		{name: "zero index", shares: []SignShare{signShares[0], func() SignShare {
			share := signShares[1]
			share.Index = 0
			return share
		}()}},
		{name: "index above players", shares: []SignShare{signShares[0], func() SignShare {
			share := signShares[1]
			share.Index = 4
			return share
		}()}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CombineSignShares(&key.PublicKey, 3, 2, tc.shares, digest)
			if err == nil {
				t.Fatal("CombineSignShares accepted an incomplete or invalid unique share set")
			}
		})
	}
}

func TestRecoveryRestartRevalidatesTransaction(t *testing.T) {
	key, _, digest, signShares := newRecoveryTestFixture(t)
	txID := []byte("tx-41022")

	recovery, err := NewRecovery(&key.PublicKey, 3, 2, txID, digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := recovery.Add(signShares[0]); err != nil {
		t.Fatal(err)
	}

	if _, err := recovery.Consume(); err == nil {
		t.Fatal("Consume succeeded with one of two shares")
	}

	// Persist after the failed attempt. The encoding contains no success
	// marker; reopening must revalidate the incomplete share set.
	persisted, err := recovery.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenRecovery(&key.PublicKey, txID, persisted)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Len() != 1 {
		t.Fatalf("reopened recovery has %d shares, want 1", reopened.Len())
	}
	if _, err := reopened.Consume(); err == nil {
		t.Fatal("reopened Consume succeeded before threshold was reached")
	}

	// Retrying the same share is idempotent, but does not complete the set.
	if err := reopened.Add(signShares[0]); err != nil {
		t.Fatalf("redelivery of identical share: %v", err)
	}
	if reopened.Len() != 1 {
		t.Fatalf("identical redelivery changed share count to %d", reopened.Len())
	}

	if err := reopened.Add(signShares[1]); err != nil {
		t.Fatal(err)
	}
	receipt, err := reopened.ConsumeReceipt()
	if err != nil {
		t.Fatalf("ConsumeReceipt: %v", err)
	}
	if !bytes.Equal(receipt.TransactionID, txID) {
		t.Fatalf("receipt transaction ID = %q, want %q", receipt.TransactionID, txID)
	}
	if len(receipt.Indices) != 2 || receipt.Indices[0] != 1 || receipt.Indices[1] != 2 {
		t.Fatalf("receipt indices = %v, want [1 2]", receipt.Indices)
	}

	hasher := crypto.SHA256.New()
	_, _ = hasher.Write([]byte("transaction-41022"))
	hashed := hasher.Sum(nil)
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, hashed, receipt.Signature); err != nil {
		t.Fatalf("verified signature: %v", err)
	}

	// An independent consumer reopens the persisted set and recomputes the
	// signature rather than trusting an in-memory or serialized success flag.
	completeState, err := reopened.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	independent, err := OpenRecovery(&key.PublicKey, txID, completeState)
	if err != nil {
		t.Fatal(err)
	}
	secondReceipt, err := independent.ConsumeReceipt()
	if err != nil {
		t.Fatalf("independent ConsumeReceipt: %v", err)
	}
	if !bytes.Equal(receipt.Signature, secondReceipt.Signature) {
		t.Fatal("independent consumer recomputed a different signature")
	}

	if _, err := OpenRecovery(&key.PublicKey, []byte("tx-other"), persisted); err == nil {
		t.Fatal("OpenRecovery accepted state for another transaction")
	}

	for name, data := range map[string][]byte{
		"empty":         nil,
		"bad magic":     []byte("not a recovery state"),
		"truncated":     persisted[:len(persisted)-1],
		"trailing byte": append(bytes.Clone(persisted), 0),
	} {
		t.Run("malformed/"+name, func(t *testing.T) {
			if _, err := OpenRecovery(&key.PublicKey, txID, data); err == nil {
				t.Fatal("OpenRecovery accepted malformed state")
			}
		})
	}

	if _, err := CombineSignShares(nil, 3, 2, signShares, digest); err == nil {
		t.Fatal("CombineSignShares accepted a nil public key")
	}
}

func TestRecoveryRejectsConflictingShare(t *testing.T) {
	key, _, _, signShares := newRecoveryTestFixture(t)
	recovery, err := NewRecovery(&key.PublicKey, 3, 2, []byte("tx-conflict"), []byte("digest"))
	if err != nil {
		t.Fatal(err)
	}
	if err := recovery.Add(signShares[0]); err != nil {
		t.Fatal(err)
	}

	conflict := signShares[0]
	conflict.xi = signShares[1].xi
	if err := recovery.Add(conflict); err == nil {
		t.Fatal("Recovery accepted two different shares with the same index")
	}
}

func TestRecoveryConcurrentRedelivery(t *testing.T) {
	key, _, digest, signShares := newRecoveryTestFixture(t)
	recovery, err := NewRecovery(&key.PublicKey, 3, 2, []byte("tx-concurrent"), digest)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := recovery.Add(signShares[0]); err != nil {
				t.Errorf("concurrent Add: %v", err)
			}
		}()
	}
	wg.Wait()

	if recovery.Len() != 1 {
		t.Fatalf("Len after concurrent redelivery = %d, want 1", recovery.Len())
	}
}

func TestRecoveryFileReopen(t *testing.T) {
	key, _, digest, signShares := newRecoveryTestFixture(t)
	txID := []byte("tx-file")
	path := filepath.Join(t.TempDir(), "recovery.bin")

	recovery, err := NewRecovery(&key.PublicKey, 3, 2, txID, digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := recovery.Add(signShares[0]); err != nil {
		t.Fatal(err)
	}
	if err := SaveRecoveryFile(path, recovery); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenRecoveryFile(path, &key.PublicKey, txID)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Len() != 1 {
		t.Fatalf("Len = %d, want 1", reopened.Len())
	}
	if err := reopened.Add(signShares[1]); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Consume(); err != nil {
		t.Fatalf("Consume after reopen: %v", err)
	}
}

func TestUnmarshalRejectsTrailingShareData(t *testing.T) {
	key, keyShares, digest, _ := newRecoveryTestFixture(t)
	signShare, err := keyShares[0].Sign(rand.Reader, &key.PublicKey, digest, false)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := signShare.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	trailing := append(bytes.Clone(encoded), 0)
	var decodedSignShare SignShare
	if err := decodedSignShare.UnmarshalBinary(trailing); err == nil {
		t.Fatal("SignShare accepted trailing data")
	}

	keyEncoded, err := keyShares[0].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	keyTrailing := append(bytes.Clone(keyEncoded), 0)
	var decodedKeyShare KeyShare
	if err := decodedKeyShare.UnmarshalBinary(keyTrailing); err == nil {
		t.Fatal("KeyShare accepted trailing data")
	}
}
