package client_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/hollis-labs/libs/security/secrets/tokenfile"

	"github.com/hollis-labs/warden/client"
)

// A fake token endpoint with strict rotation: each parent works once.
type rotating struct {
	mu      sync.Mutex
	current string
	n       int
	reused  bool
}

func (r *rotating) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	req.Body = http.MaxBytesReader(w, req.Body, 4096)
	_ = req.ParseForm()
	r.mu.Lock()
	defer r.mu.Unlock()
	if req.Form.Get("refresh_token") != r.current {
		r.reused = true
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"parent credential reuse detected"}`))
		return
	}
	r.n++
	r.current = "wdn_p_next" + strconv.Itoa(r.n)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"access_token":"tok","expires_at":"2099-01-01T00:00:00Z","refresh_token":"` + r.current + `"}`))
}

func TestMinterRotatesUnderLock(t *testing.T) {
	rt := &rotating{current: "wdn_p_first"}
	srv := httptest.NewServer(rt)
	defer srv.Close()
	file := filepath.Join(t.TempDir(), "warden.token")
	if err := tokenfile.Write(file, "wdn_p_first"); err != nil {
		t.Fatal(err)
	}
	m := &client.Minter{Client: &client.Client{BaseURL: srv.URL}, ParentFile: file, Audience: "llm-gateway"}
	// Many concurrent mints over one file: the lock serializes them, so no parent is ever presented twice.
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := m.Mint(context.Background()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if rt.reused || rt.n != 16 {
		t.Fatalf("reused=%v mints=%d", rt.reused, rt.n)
	}
	got, _ := tokenfile.Read(file)
	if got != rt.current {
		t.Fatalf("file holds %q, server expects %q", got, rt.current)
	}
	// A refused refresh surfaces the OAuth code.
	_ = tokenfile.Write(file, "wdn_p_stale")
	_, err := m.Mint(context.Background())
	if !client.IsCode(err, "invalid_grant") {
		t.Fatalf("got %v", err)
	}
}
