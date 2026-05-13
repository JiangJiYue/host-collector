//go:build !windows

package client

func EnsureElevated() error {
	return nil
}
