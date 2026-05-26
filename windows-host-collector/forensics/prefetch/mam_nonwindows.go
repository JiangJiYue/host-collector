//go:build !windows

package prefetch

import "fmt"

var decompressMAMPayload = decompressMAMPayloadUnsupported

func decompressMAMPayloadUnsupported(_ []byte, _ uint32) ([]byte, error) {
	return nil, fmt.Errorf("MAM prefetch decompression is only available on Windows")
}
