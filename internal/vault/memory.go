package vault

import (
	"context"
	"slices"
	"sync"
	"time"
)

// Memory is an in-process Backend for tests and the skeleton. It stores only sealed records.
type Memory struct {
	mu   sync.Mutex
	recs map[string][]Record // ref -> versions, oldest first
	Now  func() time.Time
}

// NewMemory builds an empty backend.
func NewMemory() *Memory { return &Memory{recs: map[string][]Record{}} }

func (m *Memory) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// NextVersion is the version the next Put of ref will get (the Sealer binds it into the AAD).
func (m *Memory) NextVersion(ref Ref) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.recs[ref.String()]) + 1
}

// Put implements Backend. r.Version must be NextVersion (sealing bound it).
func (m *Memory) Put(_ context.Context, r Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := r.Ref.String()
	if r.Version != len(m.recs[k])+1 {
		return ErrConflict
	}
	now := m.now().UTC()
	if r.Version == 1 {
		r.CreatedAt = now
	} else {
		r.CreatedAt = m.recs[k][0].CreatedAt
		r.RotatedAt = now
	}
	m.recs[k] = append(m.recs[k], r)
	return nil
}

// Get implements Backend: the newest version.
func (m *Memory) Get(_ context.Context, ref Ref) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v := m.recs[ref.String()]
	if len(v) == 0 {
		return Record{}, ErrNotFound
	}
	return v[len(v)-1], nil
}

// Metadata implements Backend.
func (m *Memory) Metadata(_ context.Context, scope string) ([]Metadata, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Metadata
	for _, v := range m.recs {
		if last := v[len(v)-1]; scope == "" || last.Ref.Scope == scope {
			out = append(out, last.Metadata)
		}
	}
	slices.SortFunc(out, func(a, b Metadata) int {
		if a.Ref.String() < b.Ref.String() {
			return -1
		}
		return 1
	})
	return out, nil
}

// Delete implements Backend.
func (m *Memory) Delete(_ context.Context, ref Ref) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.recs[ref.String()]; !ok {
		return ErrNotFound
	}
	delete(m.recs, ref.String())
	return nil
}

// ErrConflict is a concurrent write of the same reference.
var ErrConflict = errorString("vault: concurrent write")

type errorString string

func (e errorString) Error() string { return string(e) }
