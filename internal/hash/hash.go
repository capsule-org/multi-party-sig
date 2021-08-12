package hash

import (
	"errors"
	"fmt"
	"io"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/multi-party-sig/internal/params"
	"github.com/zeebo/blake3"
)

const DigestLengthBytes = params.SecBytes * 2 // 64

// Hash is the hash function we use for generating commitments, consuming CMP types, etc.
//
// Internally, this is a wrapper around sha3.ShakeHash, but any hash function with
// an easily extendable output would work as well.
type Hash struct {
	h *blake3.Hasher
}

// New creates a Hash struct where the internal hash function is initialized with "CMP-BLAKE".
func New(initialData ...WriterToWithDomain) *Hash {
	hash := &Hash{h: blake3.New()}
	_, _ = hash.h.WriteString("CMP-BLAKE")
	for _, d := range initialData {
		_ = hash.WriteAny(d)
	}
	return hash
}

// Digest returns a reader for the current output of the function.
//
// This finalizes the current state of the hash, and returns what's
// essentially a stream of random bytes.
func (hash *Hash) Digest() io.Reader {
	return hash.h.Digest()
}

// Sum returns a slice of length DigestLengthBytes resulting from the current hash state.
// If a different length is required, use io.ReadFull(hash.Digest(), out) instead.
func (hash *Hash) Sum() []byte {
	out := make([]byte, DigestLengthBytes)
	if _, err := io.ReadFull(hash.Digest(), out); err != nil {
		panic(fmt.Sprintf("hash.ReadBytes: internal hash failure: %v", err))
	}
	return out
}

// WriteAny takes many different data types and writes them to the hash state.
//
// Currently supported types:
//
//  - []byte
//  - *safenum.Nat
//  - *safenum.Int
//  - *safenum.Modulus
//  - hash.WriterToWithDomain
//
// This function will apply its own domain separation for the first two types.
// The last type already suggests which domain to use, and this function respects it.
func (hash *Hash) WriteAny(data ...interface{}) error {
	var toBeWritten WriterToWithDomain
	for _, d := range data {
		switch t := d.(type) {
		case []byte:
			if t == nil {
				return errors.New("hash.WriteAny: nil []byte")
			}
			toBeWritten = &BytesWithDomain{"[]byte", t}
		case *safenum.Nat:
			if t == nil {
				return fmt.Errorf("hash.Hash: write *safenum.Nat: nil")
			}
			toBeWritten = &BytesWithDomain{"safenum.Nat", t.Bytes()}
		case *safenum.Int:
			if t == nil {
				return fmt.Errorf("hash.Hash: write *safenum.Int: nil")
			}
			bytes, _ := t.MarshalBinary()
			toBeWritten = &BytesWithDomain{"safenum.Int", bytes}
		case *safenum.Modulus:
			if t == nil {
				return fmt.Errorf("hash.Hash: write *safenum.Modulus: nil")
			}
			toBeWritten = &BytesWithDomain{"safenum.Modulus", t.Bytes()}
		case WriterToWithDomain:
			toBeWritten = t
		default:
			panic("hash.Hash: unsupported type")
		}

		// Write out `(<domain><data>)`, so that each domain separated piece of data
		// is distinguished from others.
		_, _ = hash.h.WriteString("(")
		_, _ = hash.h.WriteString(toBeWritten.Domain())
		_, err := toBeWritten.WriteTo(hash.h)
		_, _ = hash.h.WriteString(")")
		if err != nil {
			return fmt.Errorf("hash.WriteAny: %w", err)
		}
	}
	return nil
}

// Clone returns a copy of the Hash in its current state.
func (hash *Hash) Clone() *Hash {
	return &Hash{h: hash.h.Clone()}
}