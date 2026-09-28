package tokenstore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zalando/go-keyring"
)

func sample() *Tokens {
	return &Tokens{AccessToken: "a", RefreshToken: "r", ExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Second)}
}

func TestKeychainRoundTrip(t *testing.T) {
	keyring.MockInit()
	s := &Store{Dir: t.TempDir()}
	if got, err := s.Load("p"); err != nil || got != nil {
		t.Fatalf("empty load: %v %v", got, err)
	}
	if err := s.Save("p", sample()); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load("p")
	if err != nil || got.AccessToken != "a" || got.RefreshToken != "r" {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(s.Dir, "p.json")); !os.IsNotExist(err) {
		t.Fatal("file must not be written when keychain works")
	}
	if err := s.Delete("p"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Load("p"); got != nil {
		t.Fatal("expected nil after delete")
	}
}

func TestFileFallbackPermissions(t *testing.T) {
	keyring.MockInitWithError(errors.New("no keychain"))
	dir := filepath.Join(t.TempDir(), "tokens")
	s := &Store{Dir: dir}
	if err := s.Save("p", sample()); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, "p.json"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("file mode %v %v", fi, err)
	}
	di, _ := os.Stat(dir)
	if di.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", di.Mode().Perm())
	}
	got, err := s.Load("p")
	if err != nil || got.AccessToken != "a" {
		t.Fatalf("%+v %v", got, err)
	}
}

// TestSaveTightensExistingLooseDir checks Save chmods the token dir to 0700
// even when it already existed with looser permissions (os.MkdirAll alone
// leaves an existing directory's mode untouched).
func TestSaveTightensExistingLooseDir(t *testing.T) {
	keyring.MockInitWithError(errors.New("no keychain"))
	dir := filepath.Join(t.TempDir(), "tokens")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	s := &Store{Dir: dir}
	if err := s.Save("p", sample()); err != nil {
		t.Fatal(err)
	}
	di, err := os.Stat(dir)
	if err != nil || di.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode = %v, err = %v", di.Mode().Perm(), err)
	}
}

func TestCorruptFileTreatedAsEmpty(t *testing.T) {
	keyring.MockInitWithError(errors.New("no keychain"))
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "p.json"), []byte("{not json"), 0o600)
	got, err := (&Store{Dir: dir}).Load("p")
	if err != nil || got != nil {
		t.Fatalf("want nil,nil got %v %v", got, err)
	}
}

func TestDeleteRemovesFallbackFileWhenKeychainUnavailable(t *testing.T) {
	keyring.MockInitWithError(errors.New("no keychain"))
	dir := t.TempDir()
	s := &Store{Dir: dir}
	if err := s.Save("p", sample()); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete("p"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "p.json")); !os.IsNotExist(err) {
		t.Fatalf("want file gone, stat err = %v", err)
	}
}

func TestLoadUnreadableFileReturnsErrorWithPath(t *testing.T) {
	keyring.MockInitWithError(errors.New("no keychain"))
	dir := t.TempDir()
	path := filepath.Join(dir, "p.json")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	got, err := (&Store{Dir: dir}).Load("p")
	if got != nil {
		t.Fatalf("want nil tokens, got %+v", got)
	}
	if err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("want error containing %q, got %v", path, err)
	}
}

func TestValid(t *testing.T) {
	now := time.Now()
	if (&Tokens{AccessToken: "a", ExpiresAt: now.Add(59 * time.Second)}).Valid(now) {
		t.Fatal("59s left must be invalid")
	}
	if !(&Tokens{AccessToken: "a", ExpiresAt: now.Add(61 * time.Second)}).Valid(now) {
		t.Fatal("61s left must be valid")
	}
	if (&Tokens{ExpiresAt: now.Add(time.Hour)}).Valid(now) {
		t.Fatal("empty token must be invalid")
	}
}

func TestLockExcludesOtherHolders(t *testing.T) {
	dir := t.TempDir()
	a, b := &Store{Dir: dir}, &Store{Dir: dir}
	unlock, err := a.Lock(context.Background(), "p")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	if _, err := b.Lock(ctx, "p"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second Lock while held: err=%v, want deadline exceeded", err)
	}
	unlock()
	unlock2, err := b.Lock(context.Background(), "p")
	if err != nil {
		t.Fatalf("Lock after release: %v", err)
	}
	unlock2()
}
