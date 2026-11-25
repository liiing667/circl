package hpke

// Shim to use generic KEM (kem.Scheme) as HPKE KEM.

import (
	"github.com/cloudflare/circl/internal/sha3"
	"github.com/cloudflare/circl/kem"
)

// genericNoAuthKEM wraps a generic KEM (kem.Scheme) to be used as a HPKE KEM.
type genericNoAuthKEM struct {
	kem.Scheme
	name string
}

func (h genericNoAuthKEM) Name() string { return h.name }

// HPKE requires DeriveKeyPair() to take any seed larger than the private key
// size, whereas typical KEMs expect a specific seed size. We'll just use
// SHAKE256 to hash it to the right size as in X-Wing.
func (h genericNoAuthKEM) DeriveKeyPair(seed []byte) (kem.PublicKey, kem.PrivateKey) {
	seed2 := make([]byte, h.Scheme.SeedSize())
	hh := sha3.NewShake256()
	_, _ = hh.Write(seed)
	_, _ = hh.Read(seed2)
	pk, sk := h.Scheme.DeriveKeyPair(seed2)
	return h.wrapPublicKey(pk), h.wrapPrivateKey(sk)
}

func (h genericNoAuthKEM) GenerateKeyPair() (kem.PublicKey, kem.PrivateKey, error) {
	pk, sk, err := h.Scheme.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	return h.wrapPublicKey(pk), h.wrapPrivateKey(sk), nil
}

func (h genericNoAuthKEM) UnmarshalBinaryPublicKey(data []byte) (kem.PublicKey, error) {
	pk, err := h.Scheme.UnmarshalBinaryPublicKey(data)
	if err != nil {
		return nil, err
	}
	return h.wrapPublicKey(pk), nil
}

func (h genericNoAuthKEM) UnmarshalBinaryPrivateKey(data []byte) (kem.PrivateKey, error) {
	sk, err := h.Scheme.UnmarshalBinaryPrivateKey(data)
	if err != nil {
		return nil, err
	}
	return h.wrapPrivateKey(sk), nil
}

func (h genericNoAuthKEM) Encapsulate(pk kem.PublicKey) (ct, ss []byte, err error) {
	innerPK, err := h.unwrapPublicKey(pk)
	if err != nil {
		return nil, nil, err
	}
	return h.Scheme.Encapsulate(innerPK)
}

func (h genericNoAuthKEM) EncapsulateDeterministically(
	pk kem.PublicKey, seed []byte,
) (ct, ss []byte, err error) {
	innerPK, err := h.unwrapPublicKey(pk)
	if err != nil {
		return nil, nil, err
	}
	return h.Scheme.EncapsulateDeterministically(innerPK, seed)
}

func (h genericNoAuthKEM) Decapsulate(sk kem.PrivateKey, ct []byte) ([]byte, error) {
	innerSK, err := h.unwrapPrivateKey(sk)
	if err != nil {
		return nil, err
	}
	return h.Scheme.Decapsulate(innerSK, ct)
}

func (h genericNoAuthKEM) unwrapPublicKey(pk kem.PublicKey) (kem.PublicKey, error) {
	wrapped, ok := pk.(*genericNoAuthKEMPublicKey)
	if !ok {
		// Keys generated directly by the underlying scheme, such as
		// kem/xwing.Scheme(), implement the same algorithm and remain valid.
		return pk, nil
	}
	if wrapped.scheme.name != h.name {
		return nil, kem.ErrTypeMismatch
	}
	return wrapped.key, nil
}

func (h genericNoAuthKEM) unwrapPrivateKey(sk kem.PrivateKey) (kem.PrivateKey, error) {
	wrapped, ok := sk.(*genericNoAuthKEMPrivateKey)
	if !ok {
		return sk, nil
	}
	if wrapped.scheme.name != h.name {
		return nil, kem.ErrTypeMismatch
	}
	return wrapped.key, nil
}

func (h genericNoAuthKEM) wrapPublicKey(pk kem.PublicKey) kem.PublicKey {
	if pk == nil {
		return nil
	}
	return &genericNoAuthKEMPublicKey{scheme: h, key: pk}
}

func (h genericNoAuthKEM) wrapPrivateKey(sk kem.PrivateKey) kem.PrivateKey {
	if sk == nil {
		return nil
	}
	return &genericNoAuthKEMPrivateKey{scheme: h, key: sk}
}

// genericNoAuthKEMPublicKey attaches the HPKE KEM identity to a generic KEM
// public key.
type genericNoAuthKEMPublicKey struct {
	scheme genericNoAuthKEM
	key    kem.PublicKey
}

func (k *genericNoAuthKEMPublicKey) Scheme() kem.Scheme { return k.scheme }

func (k *genericNoAuthKEMPublicKey) MarshalBinary() ([]byte, error) {
	return k.key.MarshalBinary()
}

func (k *genericNoAuthKEMPublicKey) Equal(pk kem.PublicKey) bool {
	if other, ok := pk.(*genericNoAuthKEMPublicKey); ok {
		return k.scheme.name == other.scheme.name && k.key.Equal(other.key)
	}
	return false
}

// genericNoAuthKEMPrivateKey attaches the HPKE KEM identity to a generic KEM
// private key.
type genericNoAuthKEMPrivateKey struct {
	scheme genericNoAuthKEM
	key    kem.PrivateKey
}

func (k *genericNoAuthKEMPrivateKey) Scheme() kem.Scheme { return k.scheme }

func (k *genericNoAuthKEMPrivateKey) MarshalBinary() ([]byte, error) {
	return k.key.MarshalBinary()
}

func (k *genericNoAuthKEMPrivateKey) Equal(sk kem.PrivateKey) bool {
	if other, ok := sk.(*genericNoAuthKEMPrivateKey); ok {
		return k.scheme.name == other.scheme.name && k.key.Equal(other.key)
	}
	return false
}

func (k *genericNoAuthKEMPrivateKey) Public() kem.PublicKey {
	return k.scheme.wrapPublicKey(k.key.Public())
}
