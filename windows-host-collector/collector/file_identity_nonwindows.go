//go:build !windows

package collector

import "windows-host-collector/models"

func applyWindowsFileTrust(path string, identity *models.FileIdentity) {
	if identity.SignatureState == "" || identity.SignatureState == "unknown" {
		identity.SignatureState = "unsupported"
	}
}
