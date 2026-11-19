package issuer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	libauth "github.com/hollis-labs/libs/security/auth"
)

func kids(t *testing.T, ks *KeyStore) []string {
	t.Helper()
	var doc struct {
		Keys []struct{ Kid string } `json:"keys"`
	}
	if err := json.Unmarshal(ks.JWKS(), &doc); err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, k := range doc.Keys {
		out = append(out, k.Kid)
	}
	return out
}

func TestRotationOverlap(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	dir := t.TempDir()
	ks, err := open(dir, time.Hour, clock)
	if err != nil {
		t.Fatal(err)
	}
	old, _ := ks.Active()
	tok, _, err := ks.Sign(Claims{Iss: "w", Sub: "a", Aud: "x", JTI: "1", Exp: now.Add(15 * time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if err = ks.Rotate(); err != nil {
		t.Fatal(err)
	}
	cur, _ := ks.Active()
	if cur == old {
		t.Fatal("rotation kept the same key")
	}
	if got := kids(t, ks); len(got) != 2 {
		t.Fatalf("during overlap the JWKS has %v, want both keys", got)
	}
	if _, err = ks.Verify(tok, "w", now); err != nil {
		t.Fatalf("a token of the retired key fails during overlap: %v", err)
	}
	now = now.Add(time.Hour + time.Second)
	if removed, xerr := ks.Prune(); xerr != nil || !removed {
		t.Fatalf("prune: %v %v", removed, err)
	}
	if got := kids(t, ks); len(got) != 1 || got[0] != cur {
		t.Fatalf("after overlap the JWKS has %v, want only %s", got, cur)
	}
	if _, err = os.Stat(filepath.Join(dir, old+".key")); !os.IsNotExist(err) {
		t.Fatal("the pruned key's file is still on disk")
	}
	// Reopening reads the same active key back.
	ks2, err := open(dir, time.Hour, clock)
	if err != nil {
		t.Fatal(err)
	}
	if k, _ := ks2.Active(); k != cur {
		t.Fatalf("reopened active %s, want %s", k, cur)
	}
}

func TestRefusesLooseKeyFiles(t *testing.T) {
	dir := t.TempDir()
	ks, err := Open(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	kid, _ := ks.Active()
	if err := os.Chmod(filepath.Join(dir, kid+".key"), 0o644); err != nil { //nolint:gosec // G302: the test makes the file too open on purpose
		t.Fatal(err)
	}
	if _, err := Open(dir, 0); err == nil {
		t.Fatal("a 0644 signing key was accepted")
	}
}

func TestVerifyRejects(t *testing.T) {
	now := time.Now()
	ks, _ := open(t.TempDir(), 0, func() time.Time { return now })
	good := Claims{Iss: "w", Sub: "a", Aud: "x", JTI: "1", Exp: now.Add(time.Minute).Unix()}
	tok, _, _ := ks.Sign(good)
	if _, err := ks.Verify(tok, "other", now); err == nil {
		t.Error("wrong issuer accepted")
	}
	if _, err := ks.Verify(tok, "w", now.Add(2*time.Minute)); err == nil {
		t.Error("expired token accepted")
	}
	other, _ := open(t.TempDir(), 0, func() time.Time { return now })
	forged, _, _ := other.Sign(good)
	if _, err := ks.Verify(forged, "w", now); err == nil {
		t.Error("token signed by another key ring accepted")
	}
	if _, err := ks.Verify(tok[:len(tok)-2]+"AA", "w", now); err == nil {
		t.Error("tampered signature accepted")
	}
}

// Interop: a Warden token verifies with libs/security/auth's stock JWTVerifier against Warden's JWKS, so
// every resource server that already uses libs auth trusts Warden by configuration alone.
func TestLibsVerifierAcceptsWardenTokens(t *testing.T) {
	ks, err := Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(ks.JWKS()) }))
	defer srv.Close()
	now := time.Now()
	tok, _, err := ks.Sign(Claims{Iss: "https://warden.test", Sub: "app:surface", Aud: "llm-gateway", Scope: "llm-gateway.decide llm-gateway.embed",
		Iat: now.Unix(), Nbf: now.Unix(), Exp: now.Add(time.Hour).Unix(), JTI: "j1", Kind: "app", SID: "fam_1", Par: "fam_1", Grant: "grt_1",
		Act: &Actor{Sub: "agent:lead", Kind: "agent"}})
	if err != nil {
		t.Fatal(err)
	}
	deny := libauth.NewDenyList()
	v, err := libauth.NewJWTVerifier(libauth.JWTConfig{Issuer: "https://warden.test", Audience: "llm-gateway", JWKSURL: srv.URL, DenyList: deny})
	if err != nil {
		t.Fatal(err)
	}
	p, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("libs verifier refused a Warden token: %v", err)
	}
	if p.ID != "app:surface" || p.Kind != "app" || p.SessionID != "fam_1" || len(p.Scopes) != 2 || !p.HasScope("llm-gateway.decide") {
		t.Fatalf("principal %+v", p)
	}
	// The wrong audience is refused by the stock verifier.
	v2, _ := libauth.NewJWTVerifier(libauth.JWTConfig{Issuer: "https://warden.test", Audience: "tesseract", JWKSURL: srv.URL})
	if _, err := v2.Verify(context.Background(), tok); err == nil {
		t.Fatal("an llm-gateway token verified for tesseract")
	}
	// Revoking the family (sid) through the deny-list document is honored by the stock verifier.
	deny.Replace(libauth.DenyListDoc{SID: []string{"fam_1"}})
	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("a revoked family's token verified")
	}
}
