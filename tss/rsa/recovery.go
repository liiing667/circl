package rsa

import (
	"crypto/rsa"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"
	"sort"
	"sync"
)

// recoveryMagic identifies the recovery-state encoding and its version.
var recoveryMagic = [8]byte{'C', 'I', 'R', 'C', 'L', 'T', 'S', '1'}

// Recovery collects sign shares for one transaction.
//
// A Recovery is intentionally stateless apart from its in-memory share set.
// Services can persist the bytes returned by MarshalBinary atomically and pass
// them to OpenRecovery after a restart. Opening does not trust a cached
// completion marker: Consume always revalidates the share set and recomputes
// and verifies the signature against the transaction's signing input.
type Recovery struct {
	mu            sync.RWMutex
	pub           *rsa.PublicKey
	transactionID []byte
	digest        []byte
	players       uint
	threshold     uint
	shares        map[uint]SignShare
}

// Receipt binds a verified combined signature to its originating transaction.
type Receipt struct {
	// TransactionID is the opaque service identifier for the transaction.
	TransactionID []byte
	// Digest is the padded/hash signing input committed to by Signature.
	Digest []byte
	// Signature is the recombined and self-verified threshold signature.
	Signature Signature
	// Indices are the unique player shares used to produce Signature.
	Indices []uint
}

// NewRecovery creates an empty share collector for one transaction.
//
// transactionID is an opaque service identifier used for audit and recovery.
// digest is the padded and hashed signing input passed to KeyShare.Sign and
// CombineSignShares.
func NewRecovery(
	pub *rsa.PublicKey,
	players, threshold uint,
	transactionID, digest []byte,
) (*Recovery, error) {
	if pub == nil || pub.N == nil {
		return nil, errors.New("rsa_threshold: invalid RSA public key")
	}
	if len(transactionID) == 0 {
		return nil, errors.New("rsa_threshold: transaction ID is required")
	}
	if len(digest) == 0 {
		return nil, errors.New("rsa_threshold: signing input is required")
	}
	if err := validateParams(players, threshold); err != nil {
		return nil, err
	}

	return &Recovery{
		pub:           pub,
		transactionID: append([]byte(nil), transactionID...),
		digest:        append([]byte(nil), digest...),
		players:       players,
		threshold:     threshold,
		shares:        make(map[uint]SignShare),
	}, nil
}

// TransactionID returns a copy of the transaction identity.
func (r *Recovery) TransactionID() []byte {
	if r == nil {
		return nil
	}
	return append([]byte(nil), r.transactionID...)
}

// Digest returns a copy of the transaction's padded signing input.
func (r *Recovery) Digest() []byte {
	if r == nil {
		return nil
	}
	return append([]byte(nil), r.digest...)
}

// Len returns the number of distinct accepted player shares.
func (r *Recovery) Len() int {
	if r == nil {
		return 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.shares)
}

// Add accepts a share after validating its protocol parameters and index.
//
// Redelivery of the same share is idempotent. A different share with the same
// player index is rejected. The threshold is not required to call Add; this
// allows a service to persist an incomplete collection before restarting.
func (r *Recovery) Add(share SignShare) error {
	if r == nil {
		return errors.New("rsa_threshold: nil recovery state")
	}
	if err := validateShare(r.players, r.threshold, &share); err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if previous, ok := r.shares[share.Index]; ok {
		if previous.xi == nil || share.xi.Cmp(previous.xi) != 0 {
			return fmt.Errorf("rsa_threshold: conflicting share for index %d", share.Index)
		}
		return nil
	}

	cp := share
	cp.xi = new(big.Int).Set(share.xi)
	r.shares[share.Index] = cp
	return nil
}

// Shares returns the accepted shares ordered by player index.
func (r *Recovery) Shares() []SignShare {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.shares) == 0 {
		return nil
	}
	return r.sortedSharesLocked()
}

func (r *Recovery) sortedSharesLocked() []SignShare {
	indices := make([]uint, 0, len(r.shares))
	for index := range r.shares {
		indices = append(indices, index)
	}
	sort.Slice(indices, func(i, j int) bool { return indices[i] < indices[j] })

	shares := make([]SignShare, 0, len(indices))
	for _, index := range indices {
		share := r.shares[index]
		if share.xi != nil {
			share.xi = new(big.Int).Set(share.xi)
		}
		shares = append(shares, share)
	}
	return shares
}

// Consume recombines and verifies the current share set.
//
// Unlike reading a persisted "complete" flag, this always performs the public
// share-set checks and RSA verification.
func (r *Recovery) Consume() (Signature, error) {
	receipt, err := r.ConsumeReceipt()
	if err != nil {
		return nil, err
	}
	return receipt.Signature, nil
}

// ConsumeReceipt performs the same work as Consume and additionally returns a
// receipt binding the signature to the transaction.
func (r *Recovery) ConsumeReceipt() (*Receipt, error) {
	if r == nil {
		return nil, errors.New("rsa_threshold: nil recovery state")
	}

	shares := r.Shares()
	signature, err := CombineSignShares(r.pub, r.players, r.threshold, shares, r.digest)
	if err != nil {
		return nil, err
	}

	indices := make([]uint, 0, len(shares))
	for _, share := range shares {
		indices = append(indices, share.Index)
	}

	return &Receipt{
		TransactionID: r.TransactionID(),
		Digest:        r.Digest(),
		Signature:     signature,
		Indices:       indices,
	}, nil
}

// MarshalBinary encodes the incomplete or complete share collection.
//
// The encoding contains no completion marker or cached signature. Persist the
// returned bytes atomically, for example with a temporary file in the same
// directory followed by rename.
func (r *Recovery) MarshalBinary() ([]byte, error) {
	if r == nil {
		return nil, errors.New("rsa_threshold: nil recovery state")
	}
	if len(r.transactionID) > math.MaxUint32 || len(r.digest) > math.MaxUint32 {
		return nil, errors.New("rsa_threshold: recovery field is too long")
	}
	if r.players > math.MaxUint32 || r.threshold > math.MaxUint32 {
		return nil, errors.New("rsa_threshold: recovery parameters are too large")
	}
	shares := r.Shares()
	if uint64(len(shares)) > math.MaxUint32 {
		return nil, errors.New("rsa_threshold: too many recovery shares")
	}

	out := make([]byte, 0, 64+len(r.transactionID)+len(r.digest))
	out = append(out, recoveryMagic[:]...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(r.transactionID)))
	out = append(out, r.transactionID...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(r.digest)))
	out = append(out, r.digest...)
	out = binary.BigEndian.AppendUint32(out, uint32(r.players))
	out = binary.BigEndian.AppendUint32(out, uint32(r.threshold))
	out = binary.BigEndian.AppendUint32(out, uint32(len(shares)))

	for _, share := range shares {
		encoded, err := share.MarshalBinary()
		if err != nil {
			return nil, err
		}
		if len(encoded) > math.MaxUint32 {
			return nil, errors.New("rsa_threshold: encoded share is too long")
		}
		out = binary.BigEndian.AppendUint32(out, uint32(len(encoded)))
		out = append(out, encoded...)
	}

	return out, nil
}

// OpenRecovery decodes persisted recovery state and checks that it belongs to
// expectedTransactionID. The public key is not persisted and must be supplied
// from trusted local configuration after restart.
func OpenRecovery(pub *rsa.PublicKey, expectedTransactionID, data []byte) (*Recovery, error) {
	if len(expectedTransactionID) == 0 {
		return nil, errors.New("rsa_threshold: expected transaction ID is required")
	}
	if len(data) < len(recoveryMagic) || string(data[:len(recoveryMagic)]) != string(recoveryMagic[:]) {
		return nil, errors.New("rsa_threshold: invalid recovery encoding")
	}

	pos := len(recoveryMagic)
	transactionID, pos, err := readRecoveryBytes(data, pos)
	if err != nil {
		return nil, err
	}
	digest, pos, err := readRecoveryBytes(data, pos)
	if err != nil {
		return nil, err
	}
	players32, pos, err := readRecoveryUint32(data, pos)
	if err != nil {
		return nil, err
	}
	threshold32, pos, err := readRecoveryUint32(data, pos)
	if err != nil {
		return nil, err
	}
	count32, pos, err := readRecoveryUint32(data, pos)
	if err != nil {
		return nil, err
	}

	recovery, err := NewRecovery(pub, uint(players32), uint(threshold32), transactionID, digest)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(recovery.transactionID, expectedTransactionID) != 1 {
		return nil, errors.New("rsa_threshold: recovery transaction ID mismatch")
	}

	for range count32 {
		encoded, next, err := readRecoveryBytes(data, pos)
		if err != nil {
			return nil, err
		}
		pos = next

		var share SignShare
		if err := share.UnmarshalBinary(encoded); err != nil {
			return nil, err
		}
		if err := recovery.Add(share); err != nil {
			return nil, err
		}
	}

	if pos != len(data) {
		return nil, errors.New("rsa_threshold: trailing data after recovery state")
	}

	return recovery, nil
}

func readRecoveryUint32(data []byte, pos int) (uint32, int, error) {
	if pos < 0 || pos+4 > len(data) {
		return 0, pos, errors.New("rsa_threshold: short recovery field header")
	}
	return binary.BigEndian.Uint32(data[pos : pos+4]), pos + 4, nil
}

func readRecoveryBytes(data []byte, pos int) ([]byte, int, error) {
	length, pos, err := readRecoveryUint32(data, pos)
	if err != nil {
		return nil, pos, err
	}
	if uint64(length) > uint64(len(data)-pos) {
		return nil, pos, errors.New("rsa_threshold: short recovery field value")
	}
	value := append([]byte(nil), data[pos:pos+int(length)]...)
	return value, pos + int(length), nil
}
