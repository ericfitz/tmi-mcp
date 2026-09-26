// Package tokenstore persists OAuth tokens per profile, preferring the OS
// keychain and falling back to a permission-restricted file on disk.
package tokenstore

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/zalando/go-keyring"
)

const keychainService = "tmi-mcp"

// Tokens holds an OAuth access/refresh token pair for a profile.
type Tokens struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// Valid reports whether the access token is present and has more than 60s
// left before expiry, as of now.
func (t *Tokens) Valid(now time.Time) bool {
	return t.AccessToken != "" && t.ExpiresAt.Sub(now) > 60*time.Second
}

// Store loads and saves Tokens, preferring the OS keychain and falling back
// to a JSON file under Dir when the keychain is unavailable.
type Store struct{ Dir string }

var fileFallbackWarnOnce sync.Once

func warnFileFallback() {
	fileFallbackWarnOnce.Do(func() {
		fmt.Fprintln(os.Stderr, "tmi-mcp: keychain unavailable, falling back to file storage for tokens")
	})
}

func (s *Store) filePath(profile string) string {
	return filepath.Join(s.Dir, profile+".json")
}

// Load returns the stored tokens for profile, or (nil, nil) if none are
// stored or the stored data is corrupt.
func (s *Store) Load(profile string) (*Tokens, error) {
	data, err := keyring.Get(keychainService, profile)
	if err == nil {
		return parseTokens([]byte(data), "keychain")
	}
	// keyring.ErrNotFound or any other keychain error: fall back to file.
	return s.loadFile(profile)
}

func (s *Store) loadFile(profile string) (*Tokens, error) {
	path := s.filePath(profile)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read token file %s: %w", path, err)
	}
	return parseTokens(data, path)
}

// parseTokens parses stored token JSON. On corrupt data it warns to stderr
// naming source (a file path or "keychain", never token values) and returns
// (nil, nil) so the caller treats it as absent.
func parseTokens(data []byte, source string) (*Tokens, error) {
	var t Tokens
	if err := json.Unmarshal(data, &t); err != nil {
		fmt.Fprintf(os.Stderr, "tmi-mcp: stored tokens in %s are corrupt, ignoring\n", source)
		return nil, nil
	}
	return &t, nil
}

// Save stores t for profile in the keychain, falling back to a file under
// Dir if the keychain write fails. On a successful keychain write, any
// stale fallback file is removed.
func (s *Store) Save(profile string, t *Tokens) error {
	data, err := json.Marshal(t)
	if err != nil {
		return err
	}
	if err := keyring.Set(keychainService, profile, string(data)); err == nil {
		_ = os.Remove(s.filePath(profile))
		return nil
	}
	warnFileFallback()
	return s.saveFile(profile, data)
}

func (s *Store) saveFile(profile string, data []byte) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.Dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }() // no-op once renamed

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, s.filePath(profile))
}

// Delete removes profile's tokens from both the keychain and the fallback
// file. Keychain errors (including "not found" or an unavailable keychain)
// are ignored, matching Load/Save's treatment of the keychain as optional;
// the file removal is always attempted, and only a non-"not found" file
// error is returned.
func (s *Store) Delete(profile string) error {
	_ = keyring.Delete(keychainService, profile)
	if err := os.Remove(s.filePath(profile)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
