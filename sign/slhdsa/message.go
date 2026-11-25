package slhdsa

import (
	"crypto"
	"hash"
	"io"

	"github.com/cloudflare/circl/xof"
	_ "golang.org/x/crypto/sha3"
)

// [PreHash] is a helper for hashing a message before signing.
// It implements the [io.Writer] interface, so the message can be provided
// in chunks before calling the [SignDeterministic], [SignRandomized], or
// [Verify] functions.
// Pre-hash must not be used for generating pure signatures.
type PreHash struct {
	writer interface {
		io.Writer
		Reset()
	}
	size int
	oid  byte
}

// [NewPreHashWithHash] is used to prehash messages using either the SHA2 or
// SHA3 hash functions.
// Returns [ErrPreHash] if the function is not supported.
func NewPreHashWithHash(h crypto.Hash) (*PreHash, error) {
	oid, ok := preHashOID(h)
	if !ok || !h.Available() {
		return nil, ErrPreHash
	}

	return &PreHash{h.New(), h.Size(), oid}, nil
}

func preHashOID(h crypto.Hash) (byte, bool) {
	// See the NIST Computer Security Objects Register for the suffixes of
	// the pre-hash algorithm OIDs used by FIPS 205. An explicit switch keeps
	// unknown and out-of-range identifiers from aliasing another entry in a
	// sparse lookup table.
	switch h {
	case crypto.SHA256:
		return 1, true
	case crypto.SHA384:
		return 2, true
	case crypto.SHA512:
		return 3, true
	case crypto.SHA224:
		return 4, true
	case crypto.SHA512_224:
		return 5, true
	case crypto.SHA512_256:
		return 6, true
	case crypto.SHA3_224:
		return 7, true
	case crypto.SHA3_256:
		return 8, true
	case crypto.SHA3_384:
		return 9, true
	case crypto.SHA3_512:
		return 10, true
	default:
		return 0, false
	}
}

// [NewPreHashWithXof] is used to prehash messages using either SHAKE-128
// or SHAKE-256.
// Returns [ErrPreHash] if the function is not supported.
func NewPreHashWithXof(x xof.ID) (*PreHash, error) {
	switch x {
	case xof.SHAKE128:
		return &PreHash{x.New(), 32, 11}, nil
	case xof.SHAKE256:
		return &PreHash{x.New(), 64, 12}, nil
	default:
		return nil, ErrPreHash
	}
}

func (ph *PreHash) Reset()                      { ph.writer.Reset() }
func (ph *PreHash) Write(b []byte) (int, error) { return ph.writer.Write(b) }

// BuildMessage returns a [Message] for signing, and resets the writer.
func (ph *PreHash) BuildMessage() (*Message, error) {
	if ph == nil || ph.oid < 1 || ph.oid > 12 {
		return nil, ErrPreHash
	}

	// Source https://csrc.nist.gov/Projects/computer-security-objects-register/algorithm-registration
	const oidLen = 11
	oid := [oidLen]byte{
		0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, ph.oid,
	}

	msg := make([]byte, oidLen+ph.size)
	copy(msg, oid[:])
	switch f := ph.writer.(type) {
	case hash.Hash:
		msg = f.Sum(msg[:oidLen])
	case xof.XOF:
		_, err := f.Read(msg[oidLen:])
		if err != nil {
			return nil, err
		}
	default:
		return nil, ErrPreHash
	}

	ph.Reset()
	return &Message{msg, 1}, nil
}

// [Message] wraps a message for signing.
type Message struct {
	msg       []byte
	isPreHash byte
}

// For pure signatures, use [NewMessage] to pass the message to be signed.
// For pre-hashed signatures, use [PreHash] to hash the message first, and
// then use [PreHash.BuildMessage] to get a [Message] to be signed.
func NewMessage(msg []byte) *Message { return &Message{msg, 0} }

func (m *Message) getMsgPrime(context []byte) ([]byte, error) {
	// See FIPS 205 -- Section 10.2 -- Algorithm 23 and Algorithm 25.
	const MaxContextSize = 255
	if len(context) > MaxContextSize {
		return nil, ErrContext
	}

	return append(append(
		[]byte{m.isPreHash, byte(len(context))}, context...), m.msg...,
	), nil
}
