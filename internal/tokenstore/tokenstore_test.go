package tokenstore

import (
	"errors"
	"os"
	"path/filepath"
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

func TestCorruptFileTreatedAsEmpty(t *testing.T) {
	keyring.MockInitWithError(errors.New("no keychain"))
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "p.json"), []byte("{not json"), 0o600)
	got, err := (&Store{Dir: dir}).Load("p")
	if err != nil || got != nil {
		t.Fatalf("want nil,nil got %v %v", got, err)
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
