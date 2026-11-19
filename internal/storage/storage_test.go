package storage_test

import (
	"testing"

	"github.com/hollis-labs/libs/core/store/migrate"

	"github.com/hollis-labs/warden/internal/storage"
)

// The sqlite and postgres migration directories stay in parity: same versions, so either dialect deploys.
func TestMigrationParity(t *testing.T) {
	fsys, root := storage.Migrations()
	if err := migrate.CheckParity(migrate.Source{FS: fsys, Root: root}); err != nil {
		t.Fatal(err)
	}
}
