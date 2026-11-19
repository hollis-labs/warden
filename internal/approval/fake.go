package approval

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Fake is an in-process stand-in for Gatecrasher: it keeps submitted approvals pending until Decide is
// called, then answers with a decision signed by its own key, so Warden's verifier runs exactly as it
// will against the real service. It is for tests and local development only (approvals.mode: fake).
type Fake struct {
	Issuer string // default "gatecrasher"
	Now    func() time.Time

	kid  string
	priv ed25519.PrivateKey

	mu      sync.Mutex
	byID    map[string]*fakeEntry
	byKey   map[string]string
	changed chan struct{}
}

type fakeEntry struct {
	req    Request
	ticket Ticket
}

// NewFake builds a fake with a fresh signing key.
func NewFake() *Fake {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return &Fake{kid: "fake-1", priv: priv, byID: map[string]*fakeEntry{}, byKey: map[string]string{}, changed: make(chan struct{})}
}

// Keys is the key set that verifies the fake's decisions.
func (f *Fake) Keys() StaticKeys { return StaticKeys{f.kid: f.priv.Public().(ed25519.PublicKey)} }

func (f *Fake) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

// Submit implements Approver.
func (f *Fake) Submit(_ context.Context, r Request) (Ticket, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if id, ok := f.byKey[r.IdempotencyKey]; ok {
		return f.byID[id].ticket, nil
	}
	id := fmt.Sprintf("apr_fake_%d", len(f.byID)+1)
	f.byID[id] = &fakeEntry{req: r, ticket: Ticket{ApprovalID: id, Status: Pending}}
	f.byKey[r.IdempotencyKey] = id
	return f.byID[id].ticket, nil
}

// Await implements Approver.
func (f *Fake) Await(ctx context.Context, id string, wait time.Duration) (Ticket, error) {
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	for {
		f.mu.Lock()
		e, ok := f.byID[id]
		ch := f.changed
		if !ok {
			f.mu.Unlock()
			return Ticket{}, errors.New("approval: unknown approval")
		}
		t := e.ticket
		f.mu.Unlock()
		if t.Status.Terminal() || wait <= 0 {
			return t, nil
		}
		select {
		case <-ch:
		case <-deadline.C:
			return t, nil
		case <-ctx.Done():
			return t, ctx.Err()
		}
	}
}

// Withdraw implements Approver.
func (f *Fake) Withdraw(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if e, ok := f.byID[id]; ok && e.ticket.Status == Pending {
		e.ticket.Status = Withdrawn
		f.notifyLocked()
	}
	return nil
}

// Pending lists pending approvals, oldest first (for the dev decide command and tests).
func (f *Fake) Pending() []Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	var ids []string
	for id, e := range f.byID {
		if e.ticket.Status == Pending {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	out := make([]Request, 0, len(ids))
	for _, id := range ids {
		out = append(out, f.byID[id].req)
	}
	return out
}

// ApprovalFor returns the approval id of a Warden request id.
func (f *Fake) ApprovalFor(requestID string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id, ok := f.byKey[requestID]
	return id, ok
}

// Decide records a decision by decider and signs it. narrowed may be nil.
func (f *Fake) Decide(id string, outcome Status, decider Party, narrowed *Narrowed) error {
	if outcome != Approved && outcome != Denied {
		return errors.New("approval: outcome must be approved or denied")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.byID[id]
	if !ok || e.ticket.Status != Pending {
		return errors.New("approval: no pending approval with that id")
	}
	now := f.now().UTC()
	iss := f.Issuer
	if iss == "" {
		iss = "gatecrasher"
	}
	d := Decision{Iss: iss, Aud: "warden", ApprovalID: id, RequestID: e.req.IdempotencyKey, RequestDigest: e.req.RequestDigest,
		Outcome: outcome, Tier: e.req.Tier, Decider: decider, DecidedAt: now, Exp: now.Add(MaxDecisionLife).Unix(), Narrowed: narrowed}
	jws, err := f.sign(d)
	if err != nil {
		return err
	}
	e.ticket.Status, e.ticket.Decision = outcome, jws
	f.notifyLocked()
	return nil
}

func (f *Fake) notifyLocked() {
	close(f.changed)
	f.changed = make(chan struct{})
}

// SignRaw signs an arbitrary decision with the fake's key (tests forge mismatched decisions with it).
func (f *Fake) SignRaw(d Decision) (string, error) { return f.sign(d) }

func (f *Fake) sign(d Decision) (string, error) {
	hdr, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": f.kid})
	pl, err := json.Marshal(d)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	signing := enc.EncodeToString(hdr) + "." + enc.EncodeToString(pl)
	return signing + "." + enc.EncodeToString(ed25519.Sign(f.priv, []byte(signing))), nil
}
