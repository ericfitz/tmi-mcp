//go:build !unix

package tokenstore

import "context"

// Lock is a no-op where flock is unavailable; concurrent processes may then
// race on a refresh, and the loser falls back to the rotated pair or a login.
func (s *Store) Lock(ctx context.Context, profile string) (func(), error) {
	return func() {}, nil
}
