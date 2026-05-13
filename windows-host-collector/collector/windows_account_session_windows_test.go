//go:build windows

package collector

import "testing"

func TestParseLoggedOnUsername(t *testing.T) {
	input := `\\HOST\root\cimv2:Win32_Account.Domain="DESKTOP-NJIVMOJ",Name="48967"`
	if got := parseLoggedOnUsername(input); got != "48967" {
		t.Fatalf("expected username 48967, got %q", got)
	}
}

func TestParseDependentLogonID(t *testing.T) {
	input := `\\HOST\root\cimv2:Win32_LogonSession.LogonId="0000000000003e9"`
	if got := parseDependentLogonID(input); got != "3e9" {
		t.Fatalf("expected normalized logon id 3e9, got %q", got)
	}
}

func TestParseWMIDateTime(t *testing.T) {
	input := "20260421131100.000000+480"
	got := parseWMIDateTime(input)
	if got == nil {
		t.Fatal("expected parsed time")
	}
	if *got != "2026-04-21T13:11:00+08:00" {
		t.Fatalf("expected RFC3339 +08:00 time, got %q", *got)
	}
}
