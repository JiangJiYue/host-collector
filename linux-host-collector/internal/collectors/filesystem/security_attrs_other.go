//go:build !linux

package filesystem

func collectSecurityAttributes(_ string) linuxSecurityAttributes {
	return linuxSecurityAttributes{}
}
