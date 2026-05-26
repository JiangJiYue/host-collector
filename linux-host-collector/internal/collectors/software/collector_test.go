package software

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCollectParsesDpkgStatusInstalledPackages(t *testing.T) {
	result, err := Collect(filepath.Join("..", "testdata", "root"))
	if err != nil {
		t.Fatalf("collect software: %v", err)
	}
	if len(result.Packages) != 3 {
		t.Fatalf("expected three installed packages, got %#v", result.Packages)
	}
	if len(result.Sources) != 3 || result.Sources[0] != filepath.Join("var", "lib", "dpkg", "status") || result.Sources[1] != filepath.Join("var", "log", "apt", "history.log") || result.Sources[2] != filepath.Join("var", "log", "dpkg.log") {
		t.Fatalf("unexpected software sources: %#v", result.Sources)
	}

	bash := result.Packages[0]
	if bash.Name != "bash" || bash.Version != "5.2.21-2ubuntu4" || bash.Publisher != "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>" {
		t.Fatalf("unexpected bash package metadata: %#v", bash)
	}
	if bash.PackageManager != "dpkg" || bash.Architecture != "amd64" || bash.Status != "install ok installed" || bash.Platform != "linux" {
		t.Fatalf("unexpected bash package platform fields: %#v", bash)
	}
	if bash.Size != "7164 KB" || bash.InstallLocation != "var/lib/dpkg/status" {
		t.Fatalf("unexpected bash package location/size: %#v", bash)
	}
	if bash.InstallDate != "2026-05-02T11:12:13Z" || bash.Source != filepath.Join("var", "log", "apt", "history.log") {
		t.Fatalf("expected apt upgrade history on bash package, got %#v", bash)
	}

	coreutils := result.Packages[1]
	if coreutils.Name != "coreutils" || coreutils.Source != filepath.Join("var", "log", "dpkg.log") || coreutils.InstallDate != "2026-04-30T08:00:01Z" {
		t.Fatalf("expected dpkg log fallback on coreutils package, got %#v", coreutils)
	}

	openssh := result.Packages[2]
	if openssh.Name != "openssh-server" || openssh.Source != filepath.Join("var", "log", "apt", "history.log") || openssh.InstallDate != "2026-05-01T09:10:11Z" {
		t.Fatalf("unexpected openssh package: %#v", openssh)
	}
}

func TestCollectToleratesMissingPackageDatabases(t *testing.T) {
	result, err := Collect(t.TempDir())
	if err != nil {
		t.Fatalf("collect missing software db: %v", err)
	}
	if len(result.Packages) != 0 {
		t.Fatalf("expected no packages, got %#v", result.Packages)
	}
	if len(result.Sources) != 0 {
		t.Fatalf("expected no sources, got %#v", result.Sources)
	}
}

func TestCollectParsesRpmPackageSnapshot(t *testing.T) {
	root := t.TempDir()
	rpmDir := filepath.Join(root, "var", "lib", "rpm")
	if err := os.MkdirAll(rpmDir, 0o755); err != nil {
		t.Fatalf("create rpm dir: %v", err)
	}
	snapshot := strings.Join([]string{
		"Name: bash",
		"Version: 5.2.26-5.el10",
		"Vendor: Fedora Project",
		"Architecture: x86_64",
		"InstallDate: 2026-05-04T06:07:08Z",
		"Size: 8491000",
		"",
	}, "\n")
	if err := os.WriteFile(filepath.Join(rpmDir, "Packages.txt"), []byte(snapshot), 0o644); err != nil {
		t.Fatalf("write rpm snapshot: %v", err)
	}

	result, err := Collect(root)
	if err != nil {
		t.Fatalf("collect rpm software: %v", err)
	}

	if len(result.Packages) != 1 {
		t.Fatalf("expected one rpm package, got %#v", result.Packages)
	}
	pkg := result.Packages[0]
	if pkg.Name != "bash" || pkg.Version != "5.2.26-5.el10" || pkg.Publisher != "Fedora Project" {
		t.Fatalf("unexpected rpm package identity: %#v", pkg)
	}
	if pkg.PackageManager != "rpm" || pkg.Architecture != "x86_64" || pkg.Status != "installed" || pkg.Platform != "linux" {
		t.Fatalf("unexpected rpm platform fields: %#v", pkg)
	}
	if pkg.InstallDate != "2026-05-04T06:07:08Z" || pkg.Size != "8491000 B" || pkg.Source != filepath.Join("var", "lib", "rpm", "Packages.txt") {
		t.Fatalf("unexpected rpm package evidence fields: %#v", pkg)
	}
}

func TestCollectParsesAdditionalLinuxPackageManagers(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "lib", "apk", "db", "installed"), "P:busybox\nV:1.36.1-r7\nA:aarch64\nS:1048576\n\n")
	mustWriteFile(t, filepath.Join(root, "var", "lib", "pacman", "local", "bash-5.2.026-2", "desc"), "%NAME%\nbash\n%VERSION%\n5.2.026-2\n%ARCH%\nx86_64\n%INSTALLDATE%\n1710000000\n%PACKAGER%\nArch Linux\n")
	mustWriteFile(t, filepath.Join(root, "var", "lib", "snapd", "snaps", "core20_2015.snap"), "")
	mustWriteFile(t, filepath.Join(root, "var", "lib", "flatpak", "app", "org.example.App", "current", "active", "metadata"), "[Application]\nname=org.example.App\nruntime=org.freedesktop.Platform/x86_64/23.08\n")

	result, err := Collect(root)
	if err != nil {
		t.Fatalf("collect software: %v", err)
	}

	assertPackage(t, result.Packages, "busybox", "apk", "1.36.1-r7", "aarch64")
	assertPackage(t, result.Packages, "bash", "pacman", "5.2.026-2", "x86_64")
	assertPackage(t, result.Packages, "core20", "snap", "2015", "")
	assertPackage(t, result.Packages, "org.example.App", "flatpak", "", "x86_64")
}

func assertPackage(t *testing.T, packages []Package, name string, manager string, version string, arch string) {
	t.Helper()
	for _, pkg := range packages {
		if pkg.Name != name || pkg.PackageManager != manager {
			continue
		}
		if pkg.Version != version || pkg.Architecture != arch || pkg.Platform != "linux" {
			t.Fatalf("unexpected package %s/%s: %#v", name, manager, pkg)
		}
		return
	}
	t.Fatalf("missing package %s/%s in %#v", name, manager, packages)
}

func mustWriteFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir fixture: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}
