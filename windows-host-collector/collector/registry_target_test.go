package collector

import (
	"testing"
	"windows-host-collector/models"
)

func TestTargetedRegistryPlanExcludesLowValueHKCRExtensions(t *testing.T) {
	plan := defaultTargetedRegistryPlan()

	for _, path := range []string{`.txt`, `.png`} {
		if containsRegistryTarget(plan, "HKEY_CLASSES_ROOT", path) {
			t.Fatalf("did not expect low-value HKCR extension target %q", path)
		}
	}
}

func TestTargetedRegistryPlanIncludesExecutableAssociations(t *testing.T) {
	plan := defaultTargetedRegistryPlan()

	for _, path := range []string{
		`.exe`,
		`.com`,
		`.ps1`,
		`exefile\shell\open\command`,
	} {
		if !containsRegistryTarget(plan, "HKEY_CLASSES_ROOT", path) {
			t.Fatalf("expected registry target HKEY_CLASSES_ROOT\\%s", path)
		}
	}
}

func TestTargetedRegistryPlanIncludesSystemPersistenceTargets(t *testing.T) {
	plan := defaultTargetedRegistryPlan()

	for _, target := range []struct {
		root string
		path string
	}{
		{
			root: "HKEY_LOCAL_MACHINE",
			path: `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`,
		},
		{
			root: "HKEY_LOCAL_MACHINE",
			path: `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost`,
		},
		{
			root: "HKEY_LOCAL_MACHINE",
			path: `SYSTEM\CurrentControlSet\Services`,
		},
	} {
		if !containsRegistryTarget(plan, target.root, target.path) {
			t.Fatalf("expected registry target %s\\%s", target.root, target.path)
		}
	}
}

func TestRegistryExtractReferencedPathFromCommandValues(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
	}{
		{
			name: "quoted executable command",
			data: `"C:\Users\Public\svchost.exe" -k test`,
			want: `C:\Users\Public\svchost.exe`,
		},
		{
			name: "rundll32 dll argument",
			data: `rundll32.exe C:\Temp\evil.dll,Start`,
			want: `C:\Temp\evil.dll`,
		},
		{
			name: "powershell script path",
			data: `powershell.exe -ExecutionPolicy Bypass -File C:\Users\Public\update.ps1`,
			want: `C:\Users\Public\update.ps1`,
		},
		{
			name: "environment variable service image path",
			data: `%SystemRoot%\System32\svchost.exe -k netsvcs`,
			want: `%SystemRoot%\System32\svchost.exe`,
		},
		{
			name: "environment variable service dll path",
			data: `%ProgramFiles%\Vendor\svc.dll,ServiceMain`,
			want: `%ProgramFiles%\Vendor\svc.dll`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractReferencedPathFromRegistryValue(models.RegistryValue{Data: tt.data})
			if got == nil {
				t.Fatalf("expected referenced path %q, got nil", tt.want)
			}
			if *got != tt.want {
				t.Fatalf("expected referenced path %q, got %q", tt.want, *got)
			}
		})
	}
}
