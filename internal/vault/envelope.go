package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// Alg names the envelope format.
const Alg = "A256GCM+A256GCMKW"

// Sealed is an encrypted value: the value under a per-secret data key (DEK), and the DEK under the KEK. AAD
// binds the ciphertext to its reference and version, so a sealed blob moved to another reference does not
// open.
type Sealed struct {
	Alg        string
	KEKID      string
	WrappedDEK []byte // nonce || AES-GCM(KEK, DEK)
	Nonce      []byte
	Ciphertext []byte
}

// KEK is a key-encryption key. Its bytes stay inside this package.
type KEK struct {
	id  string
	key []byte
}

// ID is a non-secret fingerprint of the KEK (which key sealed a record).
func (k KEK) ID() string { return k.id }

// NewKEK wraps 32 raw key bytes.
func NewKEK(raw []byte) (KEK, error) {
	if len(raw) != 32 {
		return KEK{}, errors.New("vault: a KEK is 32 bytes")
	}
	sum := sha256.Sum256(append([]byte("warden-kek-id:"), raw...))
	return KEK{id: "kek-" + hex.EncodeToString(sum[:6]), key: append([]byte(nil), raw...)}, nil
}

// GenerateKEK makes a fresh random KEK and its file encoding (base64, one line).
func GenerateKEK() (KEK, string, error) {
	raw := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return KEK{}, "", err
	}
	k, err := NewKEK(raw)
	return k, base64.StdEncoding.EncodeToString(raw) + "\n", err
}

// LoadKEKFile reads a root key file: a regular 0600 file holding base64 of 32 bytes. Anything looser is
// refused: the file is readable only by Warden's service user (escrow copy kept by the owner).
func LoadKEKFile(path string) (KEK, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return KEK{}, err
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o077 != 0 {
		return KEK{}, errors.New("vault: the KEK file must be a regular file readable only by its owner (0600 or 0400)")
	}
	b, err := os.ReadFile(path) //nolint:gosec // G304: an operator-configured path
	if err != nil {
		return KEK{}, err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return KEK{}, errors.New("vault: the KEK file is not base64")
	}
	return NewKEK(raw)
}

// Sealer seals and opens values under one active KEK, and opens records sealed under older KEKs it holds.
type Sealer struct {
	Active KEK
	Old    []KEK
}

func gcm(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func aadFor(ref Ref, version int) []byte {
	return fmt.Appendf(nil, "warden-vault|%s|v%d", ref, version)
}

// Seal encrypts value for ref at version.
func (s Sealer) Seal(ref Ref, version int, value []byte) (Sealed, error) {
	if len(s.Active.key) != 32 {
		return Sealed{}, errors.New("vault: no active KEK")
	}
	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return Sealed{}, err
	}
	defer clear(dek)
	aead, err := gcm(dek)
	if err != nil {
		return Sealed{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return Sealed{}, err
	}
	aad := aadFor(ref, version)
	ct := aead.Seal(nil, nonce, value, aad)
	kw, err := gcm(s.Active.key)
	if err != nil {
		return Sealed{}, err
	}
	wn := make([]byte, kw.NonceSize())
	if _, err := io.ReadFull(rand.Reader, wn); err != nil {
		return Sealed{}, err
	}
	wrapped := append(wn, kw.Seal(nil, wn, dek, aad)...)
	return Sealed{Alg: Alg, KEKID: s.Active.id, WrappedDEK: wrapped, Nonce: nonce, Ciphertext: ct}, nil
}

// ErrOpen is a sealed value that does not open (wrong key, wrong reference or version, or tampering).
var ErrOpen = errors.New("vault: sealed value does not open")

// Open decrypts a sealed value for ref at version.
func (s Sealer) Open(ref Ref, version int, sv Sealed) ([]byte, error) {
	if sv.Alg != Alg {
		return nil, ErrOpen
	}
	var kek *KEK
	for _, k := range append([]KEK{s.Active}, s.Old...) {
		if k.id == sv.KEKID {
			kek = &k
			break
		}
	}
	if kek == nil {
		return nil, ErrOpen
	}
	aad := aadFor(ref, version)
	kw, err := gcm(kek.key)
	if err != nil || len(sv.WrappedDEK) < kw.NonceSize() {
		return nil, ErrOpen
	}
	dek, err := kw.Open(nil, sv.WrappedDEK[:kw.NonceSize()], sv.WrappedDEK[kw.NonceSize():], aad)
	if err != nil {
		return nil, ErrOpen
	}
	defer clear(dek)
	aead, err := gcm(dek)
	if err != nil {
		return nil, ErrOpen
	}
	out, err := aead.Open(nil, sv.Nonce, sv.Ciphertext, aad)
	if err != nil {
		return nil, ErrOpen
	}
	return out, nil
}

// Rewrap re-wraps the DEK of sv under the active KEK without touching the ciphertext (KEK rotation).
func (s Sealer) Rewrap(ref Ref, version int, sv Sealed) (Sealed, error) {
	value, err := s.Open(ref, version, sv)
	if err != nil {
		return Sealed{}, err
	}
	defer clear(value)
	return s.Seal(ref, version, value)
}
