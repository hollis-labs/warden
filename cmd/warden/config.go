package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	libauth "github.com/hollis-labs/libs/security/auth"
	"github.com/hollis-labs/substrate/boot"
	"github.com/hollis-labs/substrate/module"
	"github.com/hollis-labs/substrate/modules/auth"
	"github.com/hollis-labs/substrate/modules/database"

	"github.com/hollis-labs/warden/internal/issuer"
	"github.com/hollis-labs/warden/internal/settings"
	"github.com/hollis-labs/warden/internal/storage"
)

// DataStore is the named store that holds Warden's tables when configured (database.stores.data).
const DataStore = "data"

// Set by start for serve: the signing keys and the deny-list the auth module's verifier reads.
var (
	issuerKeys *issuer.KeyStore
	denyList   *libauth.DenyList
)

// dataDirEnv overrides persistent application data. Operator config comes from
// SUBSTRATE_CONFIG or the optional XDG config file; secret state uses XDG_STATE_HOME.
const dataDirEnv = "WARDEN_DATA_DIR"

// dataDir is where the database, the identity signing key and the secrets state live: the
// override, else $XDG_DATA_HOME/warden, else ~/.local/share/warden.
func dataDir() (string, error) {
	if d := os.Getenv(dataDirEnv); d != "" {
		return filepath.Abs(d)
	}
	if x := os.Getenv("XDG_DATA_HOME"); x != "" {
		return filepath.Join(x, "warden"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "share", "warden"), nil
}

// runPlan is what a command line needs: which modules to start, and whether the data directory may
// be created. A command that only prints starts no module that opens or creates a file.
type runPlan struct {
	modules []string
	prepare bool // create the data directory, resolve paths into it
	issuer  bool // serve: open the signing keys and hand them to the auth module before boot
}

// printModules are what help, version, config and health need: none of them opens or creates a file.
var printModules = []string{"config", "logging", "health", "cli"}

// plan decides, from the command line, which modules to start. Only `serve`, `identity setup` and
// `identity key create` start the full set and may create the data directory, the database and the
// signing key. A bare command, help at any level, version, config, health, a bad flag and an unknown
// word start nothing that writes. Every argument that does not start with "-" counts as a command
// word. `serve` and the identity commands may create files, but a bad flag to `serve` creates none.
// (`identity setup --typo` still prepares the data directory before cobra rejects the flag: those
// commands take flags, so validating them here would duplicate the command definitions.)
// That is right only while the root command has no global flag that takes a value:
// TestRootHasNoValueFlags fails when one is added, and then plan must learn it.
func plan(args []string) runPlan {
	var words []string
	for _, a := range args {
		if a == "-h" || a == "--help" || a == "--version" || a == "help" && len(words) == 0 {
			return runPlan{modules: pick(printModules)}
		}
		if !strings.HasPrefix(a, "-") {
			words = append(words, a)
		}
	}
	switch {
	case len(words) > 0 && words[0] == "serve":
		cmd := serveCmd(context.Background(), nil)
		if err := cmd.ParseFlags(args[1:]); err == nil && len(cmd.Flags().Args()) == 0 {
			return runPlan{modules: substrateModules, prepare: true, issuer: true}
		}
	case len(words) > 1 && words[0] == "db" && words[1] == "migrate":
		// The deploy step for a Postgres data store: it migrates over the store's migration login.
		return runPlan{modules: substrateModules, prepare: true}
	case len(words) > 1 && words[0] == "identity" && (words[1] == "setup" || (words[1] == "key" && len(words) > 2 && words[2] == "create")):
		return runPlan{modules: substrateModules, prepare: true}
	}
	return runPlan{modules: pick(printModules)}
}

// pick keeps the start order of substrateModules.
func pick(want []string) []string {
	var out []string
	for _, m := range substrateModules {
		if slices.Contains(want, m) {
			out = append(out, m)
		}
	}
	return out
}

// start starts the modules of the plan. The data directory is only known at run time, so with
// prepare AfterConfig makes the file paths absolute (a path the operator's override already made
// absolute is left alone) after the SUBSTRATE_CONFIG override is applied.
func start(ctx context.Context, pl runPlan) (*boot.Running, error) {
	opts := boot.Options{}
	if pl.prepare {
		dir, err := dataDir()
		if err != nil {
			return nil, err
		}
		// Warden's tables live in the named store "data" when one is configured (Postgres in production: its
		// runtime login has no DDL rights, and `warden db migrate --store data` is the deploy step), else in
		// the default store. The default store always holds the identity module's tables, so it stays a small
		// local file that the identity module may create tables in. Registering both is harmless: a source
		// for a store that is not configured is never used.
		migrations, root := storage.Migrations()
		database.UseMigrationFS(migrations, root)
		database.UseNamedMigrationFS(DataStore, migrations, root)
		if pl.issuer {
			// Warden verifies its own tokens through the same libs verifier every resource server runs, reading
			// the key ring in process (it cannot fetch its own JWKS before its listener is up).
			ks, err := issuer.Open(filepath.Join(dir, "issuer"), issuer.DefaultOverlap)
			if err != nil {
				return nil, err
			}
			issuerKeys, denyList = ks, libauth.NewDenyList()
			auth.UseKeySource(ks.KeySource)
			auth.UseDenyList(denyList)
		}
		opts.AfterConfig = func(_ context.Context, app *module.App) error {
			cfg, _ := app.Config["auth"].(map[string]any)
			if cfg["mode"] != "enforce" {
				return fmt.Errorf("class 1 applications require auth.mode enforce")
			}
			// The guard accepts Warden tokens with iss = the configured issuer and aud = warden.
			ws, err := settings.Parse(app.Config[settings.Key])
			if err != nil {
				return err
			}
			if pl.issuer {
				cfg["issuer"] = ws.Issuer
			}
			if err = os.MkdirAll(dir, 0o700); err != nil {
				return err
			}
			state := os.Getenv("XDG_STATE_HOME")
			if state == "" {
				home, xerr := os.UserHomeDir()
				if xerr != nil {
					return xerr
				}
				state = filepath.Join(home, ".local", "state")
			}
			state, err = filepath.Abs(filepath.Join(state, substrateApp))
			if err != nil {
				return err
			}
			place(app, dir, "database", "sqlite", "path")
			place(app, dir, "identity", "key_file")
			place(app, state, "secrets", "state_dir")
			return nil
		}
	}
	return boot.StartWith(ctx, substrateApp, pl.modules, substrateConfigJSON, opts)
}

// place makes the config value at path absolute under dir, unless it already is.
func place(app *module.App, dir string, path ...string) {
	m := app.Config
	for _, k := range path[:len(path)-1] {
		child, _ := m[k].(map[string]any)
		if child == nil {
			child = map[string]any{}
			m[k] = child
		}
		m = child
	}
	key := path[len(path)-1]
	if p, _ := m[key].(string); !filepath.IsAbs(p) {
		m[key] = filepath.Join(dir, p)
	}
}
