package vault_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/hollis-labs/warden/internal/vault"
)

func TestRefs(t *testing.T) {
	r, err := vault.ParseRef("warden://llm-gateway/anthropic")
	if err != nil || r.Scope != "llm-gateway" || r.String() != "warden://llm-gateway/anthropic" {
		t.Fatalf("%+v %v", r, err)
	}
	for _, bad := range []string{"hollis://llm-gateway/anthropic", "warden://llm-gateway", "warden://LLM/x", "warden://a/../b", "warden://a//b", "keychain://x/y"} {
		if _, err := vault.ParseRef(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func sealer(t *testing.T) vault.Sealer {
	t.Helper()
	k, _, err := vault.GenerateKEK()
	if err != nil {
		t.Fatal(err)
	}
	return vault.Sealer{Active: k}
}

func TestEnvelope(t *testing.T) {
	s := sealer(t)
	ref, _ := vault.ParseRef("warden://llm-gateway/anthropic")
	secret := []byte("sk-test-not-a-real-key")
	sv, err := s.Seal(ref, 1, secret)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sv.Ciphertext, secret) || bytes.Contains(sv.WrappedDEK, secret) {
		t.Fatal("plaintext visible in the sealed record")
	}
	got, err := s.Open(ref, 1, sv)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("open: %q %v", got, err)
	}
	// Bound to its reference and version.
	other, _ := vault.ParseRef("warden://llm-gateway/openai")
	if _, err := s.Open(other, 1, sv); !errors.Is(err, vault.ErrOpen) {
		t.Error("opened under another reference")
	}
	if _, err := s.Open(ref, 2, sv); !errors.Is(err, vault.ErrOpen) {
		t.Error("opened as another version")
	}
	// Tampering is detected.
	bad := sv
	bad.Ciphertext = append([]byte(nil), sv.Ciphertext...)
	bad.Ciphertext[0] ^= 1
	if _, err := s.Open(ref, 1, bad); !errors.Is(err, vault.ErrOpen) {
		t.Error("tampered ciphertext opened")
	}
	// Another KEK cannot open it.
	if _, err := sealer(t).Open(ref, 1, sv); !errors.Is(err, vault.ErrOpen) {
		t.Error("opened with another KEK")
	}
	// Each seal uses a fresh data key.
	sv2, _ := s.Seal(ref, 1, secret)
	if bytes.Equal(sv.WrappedDEK, sv2.WrappedDEK) || bytes.Equal(sv.Ciphertext, sv2.Ciphertext) {
		t.Error("two seals share a data key or nonce")
	}
}

func TestKEKRotation(t *testing.T) {
	old := sealer(t)
	ref, _ := vault.ParseRef("warden://github/app-key")
	sv, _ := old.Seal(ref, 1, []byte("pem"))
	next := vault.Sealer{Active: sealer(t).Active, Old: []vault.KEK{old.Active}}
	if _, err := next.Open(ref, 1, sv); err != nil {
		t.Fatalf("new sealer cannot open a record under the old KEK: %v", err)
	}
	re, err := next.Rewrap(ref, 1, sv)
	if err != nil || re.KEKID != next.Active.ID() {
		t.Fatalf("rewrap: %v", err)
	}
	if _, err := (vault.Sealer{Active: next.Active}).Open(ref, 1, re); err != nil {
		t.Fatalf("rewrapped record needs the old KEK: %v", err)
	}
}

func TestKEKFile(t *testing.T) {
	dir := t.TempDir()
	_, enc, _ := vault.GenerateKEK()
	p := filepath.Join(dir, "root.key")
	if err := os.WriteFile(p, []byte(enc), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := vault.LoadKEKFile(p); err != nil {
		t.Fatalf("0600 KEK file: %v", err)
	}
	if err := os.Chmod(p, 0o640); err != nil { //nolint:gosec // G302: the test makes the file too open on purpose
		t.Fatal(err)
	}
	if _, err := vault.LoadKEKFile(p); err == nil {
		t.Fatal("a group-readable KEK file was accepted")
	}
}

func TestMemoryBackend(t *testing.T) {
	ctx := context.Background()
	s := sealer(t)
	m := vault.NewMemory()
	ref, _ := vault.ParseRef("warden://llm-gateway/anthropic")
	put := func(val string) {
		v := m.NextVersion(ref)
		sv, err := s.Seal(ref, v, []byte(val))
		if err != nil {
			t.Fatal(err)
		}
		if err := m.Put(ctx, vault.Record{Metadata: vault.Metadata{Ref: ref, Kind: vault.KindAPIKey, Delivery: []vault.Delivery{vault.Brokered}, Version: v}, Sealed: sv}); err != nil {
			t.Fatal(err)
		}
	}
	put("v1")
	put("v2")
	rec, err := m.Get(ctx, ref)
	if err != nil || rec.Version != 2 || rec.RotatedAt.IsZero() {
		t.Fatalf("get: %+v %v", rec.Metadata, err)
	}
	got, err := s.Open(ref, rec.Version, rec.Sealed)
	if err != nil || string(got) != "v2" {
		t.Fatalf("open latest: %q %v", got, err)
	}
	if err := m.Put(ctx, vault.Record{Metadata: vault.Metadata{Ref: ref, Version: 1}}); !errors.Is(err, vault.ErrConflict) {
		t.Fatal("a stale version overwrote the record")
	}
	md, _ := m.Metadata(ctx, "llm-gateway")
	if len(md) != 1 {
		t.Fatalf("metadata %+v", md)
	}
	if err := m.Delete(ctx, ref); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Get(ctx, ref); !errors.Is(err, vault.ErrNotFound) {
		t.Fatal("deleted record still readable")
	}
}
