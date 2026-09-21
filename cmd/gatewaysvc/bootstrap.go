package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/go-freya/freya/services/gateway/internal/audit"
	"github.com/go-freya/freya/services/gateway/internal/config"
	"github.com/go-freya/freya/services/gateway/internal/manifest"
	"github.com/go-freya/freya/services/gateway/internal/store"
)

type allowFlag []store.AllowEntry

func (f *allowFlag) String() string { return fmt.Sprint(len(*f)) }

// Set parses "<spiffe-id>=<prefix>[,<prefix>...][;<name>[,<name>...]]".
func (f *allowFlag) Set(v string) error {
	e, err := parseAllow(v)
	if err != nil {
		return err
	}
	*f = append(*f, e)
	return nil
}

func parseAllow(v string) (store.AllowEntry, error) {
	id, rest, ok := strings.Cut(v, "=")
	if !ok || !strings.HasPrefix(id, "spiffe://") {
		return store.AllowEntry{}, errors.New("allow: expected <spiffe-id>=<prefixes>[;<names>]")
	}
	prefixPart, namePart, _ := strings.Cut(rest, ";")
	e := store.AllowEntry{SpiffeID: id}
	for _, p := range strings.Split(prefixPart, ",") {
		n, ok := manifest.NormalizePrefix(strings.TrimSpace(p))
		if !ok {
			return store.AllowEntry{}, fmt.Errorf("allow: prefix %q", p)
		}
		e.Prefixes = append(e.Prefixes, n)
	}
	if namePart == "" {
		namePart = id[strings.LastIndex(id, "/")+1:]
	}
	for _, n := range strings.Split(namePart, ",") {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		e.Names = append(e.Names, n)
	}
	if len(e.Prefixes) == 0 || len(e.Names) == 0 {
		return store.AllowEntry{}, errors.New("allow: at least one prefix and one name are required")
	}
	return e, nil
}

func bootstrap(args []string) int {
	fs := flag.NewFlagSet("gatewaysvc bootstrap", flag.ContinueOnError)
	cfgPath := fs.String("config", "deploy/dev.yaml", "configuration file")
	var allows allowFlag
	fs.Var(&allows, "allow", "allow-list entry (repeatable): <spiffe-id>=<prefix>[,<prefix>...][;<name>,...]")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if len(allows) == 0 {
		return fail(errors.New("bootstrap: at least one -allow is required"))
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return fail(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	dsn := cfg.DB.MigrateDSN
	if dsn == "" {
		dsn = cfg.DB.DSN
	}
	if err := store.Migrate(ctx, dsn); err != nil {
		return fail(err)
	}
	st, err := store.Open(ctx, cfg.DB.DSN, 2)
	if err != nil {
		return fail(err)
	}
	defer st.Close()
	aw := audit.NewWriter(st, func(err error) { fmt.Fprintln(os.Stderr, "gatewaysvc: audit:", err) })
	defer aw.Close()
	for _, e := range allows {
		e.ID = uuid.Must(uuid.NewV7()).String()
		e.CreatedBy = "bootstrap"
		e.CreatedAt = time.Now().UTC()
		err := st.Tx(ctx, func(tx pgx.Tx) error { return store.InsertAllow(ctx, tx, e) })
		switch {
		case errors.Is(err, store.ErrConflict):
			fmt.Fprintf(os.Stderr, "gatewaysvc: %s already allowed (skipped)\n", e.SpiffeID)
			continue
		case err != nil:
			return fail(err)
		}
		_ = aw.Emit(audit.Event{Type: audit.AllowlistChanged, ActorKind: "system", ActorID: "bootstrap", SubjectKind: "allow_entry", SubjectID: e.ID, Outcome: "ok", Reason: "added",
			Details: map[string]any{"spiffe_id": e.SpiffeID, "prefixes": e.Prefixes, "names": e.Names}})
		fmt.Printf("allowed %s prefixes=%s names=%s\n", e.SpiffeID, strings.Join(e.Prefixes, ","), strings.Join(e.Names, ","))
	}
	return 0
}
