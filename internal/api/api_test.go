package api_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hollis-labs/warden/internal/api"
)

type fakeHook struct{}

func (fakeHook) PendingJSON() any                    { return nil }
func (fakeHook) Decide(string, string, string) error { return nil }

// Every route the mux serves is listed in Routes() with a scope, and the other way round: a route without
// a scope is refused in enforce mode, so it would be unreachable.
func TestEveryRouteHasAScope(t *testing.T) {
	mux := api.New(nil, api.Metadata{}, fakeHook{}).Mux()
	for _, rt := range api.Routes(true) {
		if strings.TrimSpace(rt.Scope) == "" {
			t.Errorf("%s %s has no scope", rt.Method, rt.Pattern)
		}
		_, pattern := mux.Handler(httptest.NewRequest(rt.Method, rt.Pattern, nil))
		if want := rt.Method + " " + rt.Pattern; pattern != want {
			t.Errorf("%s %s: mux serves %q, Routes() lists %q", rt.Method, rt.Pattern, pattern, want)
		}
	}
}

// The dev approval routes exist only with the fake.
func TestDevRoutesOnlyWithFake(t *testing.T) {
	mux := api.New(nil, api.Metadata{}, nil).Mux()
	for _, rt := range api.Routes(true) {
		if !strings.Contains(rt.Pattern, "/dev/") {
			continue
		}
		if _, pattern := mux.Handler(httptest.NewRequest(rt.Method, rt.Pattern, nil)); pattern != "" {
			t.Errorf("%s served without the fake", rt.Pattern)
		}
	}
}

// A caller the guard did not verify never reaches the data.
func TestUnverifiedCallerIsRefused(t *testing.T) {
	mux := api.New(nil, api.Metadata{}, fakeHook{}).Mux()
	for _, rt := range api.Routes(true) {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(rt.Method, rt.Pattern, strings.NewReader(`{}`)))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s: status %d, want 401", rt.Method, rt.Pattern, rec.Code)
		}
	}
}

// Admin routes need warden.admin, which no principal's base grant holds.
func TestAdminRoutesNeedAdmin(t *testing.T) {
	for _, rt := range api.Routes(true) {
		admin := strings.Contains(rt.Pattern, "/audit") || strings.Contains(rt.Pattern, "/keys/") || strings.Contains(rt.Pattern, "/principals/") ||
			strings.Contains(rt.Pattern, "/device/approve") || strings.Contains(rt.Pattern, "/dev/")
		if admin != (rt.Scope == api.ScopeAdmin) {
			t.Errorf("%s %s: scope %s", rt.Method, rt.Pattern, rt.Scope)
		}
	}
}
