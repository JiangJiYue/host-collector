package collector

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"windows-host-collector/models"
)

func ptr[T any](v T) *T {
	return &v
}

func TestCorrelateAccountsSAMOnlyConfirmedShadow(t *testing.T) {
	rid := uint32(1337)
	accounts := correlateAccountSources(accountSourceBundle{
		SAM: []accountSourceRecord{
			{
				Username:         "hidden_support",
				SID:              ptr("S-1-5-21-100-200-300-1337"),
				RID:              &rid,
				Source:           accountSourceSAM,
				SAMRidKey:        true,
				SAMNameIndex:     true,
				NameIndexRID:     &rid,
				RIDKeyPresent:    true,
				NameIndexPresent: true,
			},
		},
	})

	if len(accounts) != 1 {
		t.Fatalf("expected one account, got %d", len(accounts))
	}
	got := accounts[0]

	if got.ID != "user:sid:S-1-5-21-100-200-300-1337" {
		t.Fatalf("expected SID-based ID, got %q", got.ID)
	}
	if !got.Shadow.IsShadowAccount {
		t.Fatalf("expected shadow account")
	}
	if got.Shadow.Status != shadowStatusConfirmed {
		t.Fatalf("expected status %q, got %q", shadowStatusConfirmed, got.Shadow.Status)
	}
	if got.Shadow.Confidence != shadowConfidenceHigh {
		t.Fatalf("expected confidence %q, got %q", shadowConfidenceHigh, got.Shadow.Confidence)
	}
	if !slices.Contains(got.Shadow.Reasons, shadowReasonSAMOnly) {
		t.Fatalf("expected reason %q in %v", shadowReasonSAMOnly, got.Shadow.Reasons)
	}
	if got.Visibility.NetAPI || got.Visibility.WMI || !got.Visibility.SAMRidKey {
		t.Fatalf("expected only SAM visibility, got %+v", got.Visibility)
	}
}

func TestCorrelateAccountsSAMOnlyWithoutRIDKeyStillConfirmedShadow(t *testing.T) {
	accounts := correlateAccountSources(accountSourceBundle{
		SAM: []accountSourceRecord{
			{
				Username:     "hidden_support_index_only",
				Source:       accountSourceSAM,
				SAMRidKey:    false,
				SAMNameIndex: true,
			},
		},
	})

	if len(accounts) != 1 {
		t.Fatalf("expected one account, got %d", len(accounts))
	}
	got := accounts[0]
	if !got.Shadow.IsShadowAccount {
		t.Fatalf("expected shadow account")
	}
	if got.Shadow.Status != shadowStatusConfirmed {
		t.Fatalf("expected status %q, got %q", shadowStatusConfirmed, got.Shadow.Status)
	}
	if got.Shadow.Confidence != shadowConfidenceHigh {
		t.Fatalf("expected confidence %q, got %q", shadowConfidenceHigh, got.Shadow.Confidence)
	}
	if !slices.Contains(got.Shadow.Reasons, shadowReasonSAMOnly) {
		t.Fatalf("expected reason %q in %v", shadowReasonSAMOnly, got.Shadow.Reasons)
	}
}

func TestCorrelateAccountsNetCommandInvisibleConfirmedShadow(t *testing.T) {
	sid := "S-1-5-21-100063101-1421488037-1938337138-1003"
	rid := uint32(1003)
	accounts := correlateAccountSources(accountSourceBundle{
		NetAPI: []accountSourceRecord{
			{Username: "youzi$", SID: &sid, RID: &rid, Source: accountSourceNetAPI, NetAPIVisible: true},
		},
		WMI: []accountSourceRecord{
			{Username: "youzi$", SID: &sid, RID: &rid, Source: accountSourceWMI, WMIVisible: true},
		},
		NetCmd: []accountSourceRecord{},
		SAM: []accountSourceRecord{
			{
				Username:         "youzi$",
				SID:              &sid,
				RID:              &rid,
				Source:           accountSourceSAM,
				SAMRidKey:        true,
				SAMNameIndex:     true,
				NameIndexRID:     &rid,
				RIDKeyPresent:    true,
				NameIndexPresent: true,
			},
		},
	})

	if len(accounts) != 1 {
		t.Fatalf("expected one account, got %d", len(accounts))
	}
	got := accounts[0]
	if !got.Shadow.IsShadowAccount {
		t.Fatalf("expected shadow account")
	}
	if got.Shadow.Status != shadowStatusConfirmed {
		t.Fatalf("expected status %q, got %q", shadowStatusConfirmed, got.Shadow.Status)
	}
	if got.Shadow.Confidence != shadowConfidenceHigh {
		t.Fatalf("expected confidence %q, got %q", shadowConfidenceHigh, got.Shadow.Confidence)
	}
	if !slices.Contains(got.Shadow.Reasons, shadowReasonNetCommandInvisible) {
		t.Fatalf("expected reason %q in %v", shadowReasonNetCommandInvisible, got.Shadow.Reasons)
	}
	if got.Visibility.NetCommand {
		t.Fatalf("expected net command visibility to remain false, got %+v", got.Visibility)
	}
}

func TestCorrelateAccountsMatchingSourcesAreClean(t *testing.T) {
	sid := "S-1-5-21-1-2-3-500"
	rid := uint32(500)
	accounts := correlateAccountSources(accountSourceBundle{
		NetAPI: []accountSourceRecord{
			{Username: "Administrator", SID: &sid, RID: &rid, Source: accountSourceNetAPI},
		},
		WMI: []accountSourceRecord{
			{Username: "Administrator", SID: &sid, RID: &rid, Source: accountSourceWMI},
		},
		SAM: []accountSourceRecord{
			{Username: "Administrator", SID: &sid, RID: &rid, Source: accountSourceSAM, SAMRidKey: true, SAMNameIndex: true, NameIndexRID: &rid},
		},
	})

	if len(accounts) != 1 {
		t.Fatalf("expected one account, got %d", len(accounts))
	}
	got := accounts[0]
	if got.Shadow.IsShadowAccount {
		t.Fatalf("expected clean account, got shadow=%+v", got.Shadow)
	}
	if got.Shadow.Status != shadowStatusClean {
		t.Fatalf("expected status %q, got %q", shadowStatusClean, got.Shadow.Status)
	}
	if got.Shadow.Confidence != shadowConfidenceNone {
		t.Fatalf("expected confidence %q, got %q", shadowConfidenceNone, got.Shadow.Confidence)
	}
	wantSources := []string{accountSourceNetAPI, accountSourceWMI, accountSourceSAM}
	if !slices.Equal(got.Sources, wantSources) {
		t.Fatalf("expected sources %v, got %v", wantSources, got.Sources)
	}
}

func TestCorrelateAccountsPrefersSessionLogonTimeWhenPrimarySourcesAreEmpty(t *testing.T) {
	sid := "S-1-5-21-1-2-3-1001"
	rid := uint32(1001)
	sessionLogon := "2026-04-21T13:11:00+08:00"
	accounts := correlateAccountSources(accountSourceBundle{
		NetAPI: []accountSourceRecord{
			{Username: "48967", SID: &sid, RID: &rid, Source: accountSourceNetAPI},
		},
		WMI: []accountSourceRecord{
			{Username: "48967", SID: &sid, RID: &rid, Source: accountSourceWMI},
		},
		NetCmd: []accountSourceRecord{
			{Username: "48967", SID: &sid, RID: &rid, Source: accountSourceNetCmd},
		},
		SAM: []accountSourceRecord{
			{Username: "48967", SID: &sid, RID: &rid, Source: accountSourceSAM, SAMRidKey: true, SAMNameIndex: true, NameIndexRID: &rid},
		},
		Session: []accountSourceRecord{
			{Username: "48967", SID: &sid, RID: &rid, Source: accountSourceSession, LastLogon: &sessionLogon},
		},
	})

	if len(accounts) != 1 {
		t.Fatalf("expected one account, got %d", len(accounts))
	}
	got := accounts[0]
	if got.LastLogon == nil || *got.LastLogon != sessionLogon {
		t.Fatalf("expected session-derived last logon %q, got %#v", sessionLogon, got.LastLogon)
	}
	wantSources := []string{accountSourceNetAPI, accountSourceWMI, accountSourceNetCmd, accountSourceSAM, accountSourceSession}
	if !slices.Equal(got.Sources, wantSources) {
		t.Fatalf("expected sources %v, got %v", wantSources, got.Sources)
	}
}

func TestCorrelateAccountsSessionOnlyDoesNotCreateVirtualUsers(t *testing.T) {
	sessionLogon := "2026-04-21T13:11:00+08:00"
	accounts := correlateAccountSources(accountSourceBundle{
		Session: []accountSourceRecord{
			{Username: "DWM-1", Source: accountSourceSession, LastLogon: &sessionLogon},
			{Username: "UMFD-0", Source: accountSourceSession, LastLogon: &sessionLogon},
			{Username: "UMFD-1", Source: accountSourceSession, LastLogon: &sessionLogon},
		},
	})

	if len(accounts) != 0 {
		t.Fatalf("expected session-only virtual accounts to be ignored, got %#v", accounts)
	}
}

func TestStableUserIDPriority(t *testing.T) {
	rid := uint32(500)
	if got := stableUserID(ptr("S-1-5-21-1-2-3-500"), &rid, "Administrator"); got != "user:sid:S-1-5-21-1-2-3-500" {
		t.Fatalf("expected SID priority, got %q", got)
	}
	if got := stableUserID(nil, &rid, "Administrator"); got != "user:rid:500" {
		t.Fatalf("expected RID priority, got %q", got)
	}
	if got := stableUserID(nil, nil, " Admin User "); got != "user:name:admin-user" {
		t.Fatalf("expected normalized username fallback, got %q", got)
	}
}

func TestCorrelateAccountsSAMErrorSetsUnchecked(t *testing.T) {
	accounts := correlateAccountSources(accountSourceBundle{
		NetAPI: []accountSourceRecord{
			{Username: "Administrator", Source: accountSourceNetAPI},
		},
		SAMErr: errors.New("sam read denied"),
	})

	if len(accounts) != 1 {
		t.Fatalf("expected one account, got %d", len(accounts))
	}
	got := accounts[0]
	if got.Shadow.Status != shadowStatusUnchecked {
		t.Fatalf("expected status %q, got %q", shadowStatusUnchecked, got.Shadow.Status)
	}
	if got.Shadow.Confidence != shadowConfidenceNone {
		t.Fatalf("expected confidence %q, got %q", shadowConfidenceNone, got.Shadow.Confidence)
	}
	if len(got.Shadow.Reasons) != 1 || got.Shadow.Reasons[0] != shadowReasonSAMUnchecked {
		t.Fatalf("expected SAM unchecked reason, got %v", got.Shadow.Reasons)
	}
	if len(got.Shadow.Evidence) == 0 {
		t.Fatalf("expected SAM error evidence")
	}
}

func TestCorrelateAccountsSAMNotConfirmedWhenNetAPIFails(t *testing.T) {
	rid := uint32(2001)
	accounts := correlateAccountSources(accountSourceBundle{
		SAM: []accountSourceRecord{
			{
				Username:     "svc_shadow_candidate",
				Source:       accountSourceSAM,
				RID:          &rid,
				SAMRidKey:    true,
				SAMNameIndex: true,
				NameIndexRID: &rid,
			},
		},
		NetAPIErr: errors.New("netapi unavailable"),
	})

	if len(accounts) != 1 {
		t.Fatalf("expected one account, got %d", len(accounts))
	}
	got := accounts[0]
	if got.Shadow.IsShadowAccount {
		t.Fatalf("expected safe non-shadow result, got %+v", got.Shadow)
	}
	if got.Shadow.Status != shadowStatusClean || got.Shadow.Confidence != shadowConfidenceNone {
		t.Fatalf("expected clean/none, got %q/%q", got.Shadow.Status, got.Shadow.Confidence)
	}
	for _, blocked := range []string{shadowReasonSAMOnly, shadowReasonAPIInvisible, shadowReasonSourceMismatch} {
		if slices.Contains(got.Shadow.Reasons, blocked) {
			t.Fatalf("did not expect %q when NetAPI failed, got reasons=%v", blocked, got.Shadow.Reasons)
		}
	}
}

func TestCorrelateAccountsSAMNotConfirmedWhenWMIFails(t *testing.T) {
	rid := uint32(2002)
	accounts := correlateAccountSources(accountSourceBundle{
		SAM: []accountSourceRecord{
			{
				Username:     "svc_shadow_candidate",
				Source:       accountSourceSAM,
				RID:          &rid,
				SAMRidKey:    true,
				SAMNameIndex: true,
				NameIndexRID: &rid,
			},
		},
		WMIErr: errors.New("wmi unavailable"),
	})

	if len(accounts) != 1 {
		t.Fatalf("expected one account, got %d", len(accounts))
	}
	got := accounts[0]
	if got.Shadow.IsShadowAccount {
		t.Fatalf("expected safe non-shadow result, got %+v", got.Shadow)
	}
	if got.Shadow.Status != shadowStatusClean || got.Shadow.Confidence != shadowConfidenceNone {
		t.Fatalf("expected clean/none, got %q/%q", got.Shadow.Status, got.Shadow.Confidence)
	}
	for _, blocked := range []string{shadowReasonSAMOnly, shadowReasonAPIInvisible, shadowReasonSourceMismatch} {
		if slices.Contains(got.Shadow.Reasons, blocked) {
			t.Fatalf("did not expect %q when WMI failed, got reasons=%v", blocked, got.Shadow.Reasons)
		}
	}
}

func TestCorrelateAccountsSameUsernameConflictingSIDStaySeparate(t *testing.T) {
	sidA := "S-1-5-21-1-1-1-1101"
	sidB := "S-1-5-21-1-1-1-2202"
	ridA := uint32(1101)
	ridB := uint32(2202)
	accounts := correlateAccountSources(accountSourceBundle{
		NetAPI: []accountSourceRecord{
			{Username: "ops-user", SID: &sidA, RID: &ridA, Source: accountSourceNetAPI},
		},
		WMI: []accountSourceRecord{
			{Username: "ops-user", SID: &sidB, RID: &ridB, Source: accountSourceWMI},
		},
	})

	if len(accounts) != 2 {
		t.Fatalf("expected two separate accounts, got %d: %#v", len(accounts), accounts)
	}
	if accounts[0].SID == nil || accounts[1].SID == nil {
		t.Fatalf("expected both results to keep SID values, got %#v", accounts)
	}
	if *accounts[0].SID == *accounts[1].SID {
		t.Fatalf("expected conflicting SID records to remain separate, got %#v", accounts)
	}
}

func TestCorrelateAccountsSameUsernameSameSIDDifferentRIDStaySeparate(t *testing.T) {
	sid := "S-1-5-21-1-1-1-5000"
	ridA := uint32(5000)
	ridB := uint32(5001)
	accounts := correlateAccountSources(accountSourceBundle{
		NetAPI: []accountSourceRecord{
			{Username: "svc-app", SID: &sid, RID: &ridA, Source: accountSourceNetAPI},
		},
		WMI: []accountSourceRecord{
			{Username: "svc-app", SID: &sid, RID: &ridB, Source: accountSourceWMI},
		},
	})

	if len(accounts) != 2 {
		t.Fatalf("expected two accounts, got %d: %#v", len(accounts), accounts)
	}
	if accounts[0].RID == nil || accounts[1].RID == nil {
		t.Fatalf("expected both accounts to keep RID values, got %#v", accounts)
	}
	if *accounts[0].RID == *accounts[1].RID {
		t.Fatalf("expected distinct RIDs to remain separate, got %#v", accounts)
	}
}

func TestCorrelateAccountsSameUsernameSameRIDDifferentSIDStaySeparate(t *testing.T) {
	sidA := "S-1-5-21-1-1-1-6000"
	sidB := "S-1-5-21-1-1-1-7000"
	rid := uint32(7000)
	accounts := correlateAccountSources(accountSourceBundle{
		NetAPI: []accountSourceRecord{
			{Username: "svc-app", SID: &sidA, RID: &rid, Source: accountSourceNetAPI},
		},
		WMI: []accountSourceRecord{
			{Username: "svc-app", SID: &sidB, RID: &rid, Source: accountSourceWMI},
		},
	})

	if len(accounts) != 2 {
		t.Fatalf("expected two accounts, got %d: %#v", len(accounts), accounts)
	}
	if accounts[0].SID == nil || accounts[1].SID == nil {
		t.Fatalf("expected both accounts to keep SID values, got %#v", accounts)
	}
	if *accounts[0].SID == *accounts[1].SID {
		t.Fatalf("expected distinct SIDs to remain separate, got %#v", accounts)
	}
}

func TestCorrelateAccountsDeterministicOutputOrder(t *testing.T) {
	sidA := "S-1-5-21-1-2-3-500"
	sidB := "S-1-5-21-1-2-3-501"
	ridA := uint32(500)
	ridB := uint32(501)

	bundleA := accountSourceBundle{
		NetAPI: []accountSourceRecord{
			{Username: "Zulu User", SID: &sidB, RID: &ridB, Source: accountSourceNetAPI},
			{Username: "alpha-user", SID: &sidA, RID: &ridA, Source: accountSourceNetAPI},
		},
	}
	bundleB := accountSourceBundle{
		NetAPI: []accountSourceRecord{
			{Username: "alpha-user", SID: &sidA, RID: &ridA, Source: accountSourceNetAPI},
			{Username: "Zulu User", SID: &sidB, RID: &ridB, Source: accountSourceNetAPI},
		},
	}

	a := correlateAccountSources(bundleA)
	b := correlateAccountSources(bundleB)
	if len(a) != 2 || len(b) != 2 {
		t.Fatalf("expected two accounts from both bundles, got len(a)=%d len(b)=%d", len(a), len(b))
	}
	for i := range a {
		if a[i].ID != b[i].ID {
			t.Fatalf("expected deterministic order; index %d mismatch: %q vs %q", i, a[i].ID, b[i].ID)
		}
	}
	if a[0].Username != "alpha-user" {
		t.Fatalf("expected normalized username order, got first=%q", a[0].Username)
	}
}

func TestFormatAccountDiagnosticsIncludesSourcesVisibilityAndShadow(t *testing.T) {
	sid := "S-1-5-21-100063101-1421488037-1938337138-1003"
	rid := uint32(1003)
	accounts := correlateAccountSources(accountSourceBundle{
		NetAPI: []accountSourceRecord{
			{Username: "youzi$", SID: &sid, RID: &rid, Source: accountSourceNetAPI, NetAPIVisible: true},
		},
		WMI: []accountSourceRecord{
			{Username: "youzi$", SID: &sid, RID: &rid, Source: accountSourceWMI, WMIVisible: true},
		},
		NetCmd: []accountSourceRecord{},
		SAM: []accountSourceRecord{
			{
				Username:         "youzi$",
				SID:              &sid,
				RID:              &rid,
				Source:           accountSourceSAM,
				SAMRidKey:        true,
				SAMNameIndex:     true,
				NameIndexRID:     &rid,
				RIDKeyPresent:    true,
				NameIndexPresent: true,
			},
		},
	})

	if len(accounts) != 1 {
		t.Fatalf("expected one account, got %d", len(accounts))
	}

	got := formatAccountDiagnostics(accounts)
	for _, want := range []string{
		"username=youzi$",
		"sid=S-1-5-21-100063101-1421488037-1938337138-1003",
		"rid=1003",
		"sources=netApi,wmi,sam",
		"visibility=netApi:true,wmi:true,netCommand:false,samRidKey:true,samNameIndex:true",
		"shadow=confirmed/high/true",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected diagnostic output to contain %q, got %q", want, got)
		}
	}
}

func TestFormatProviderDiagnosticsHighlightsOnlySamAccounts(t *testing.T) {
	sid := "S-1-5-21-100063101-1421488037-1938337138-1003"
	rid := uint32(1003)
	got := formatProviderDiagnostics(accountSourceBundle{
		SAM: []accountSourceRecord{
			{
				Username:         "youzi$",
				SID:              &sid,
				RID:              &rid,
				Source:           accountSourceSAM,
				SAMRidKey:        true,
				SAMNameIndex:     true,
				NameIndexRID:     &rid,
				RIDKeyPresent:    true,
				NameIndexPresent: true,
			},
		},
	})

	for _, want := range []string{
		"netapi=[]",
		"wmi=[]",
		"netcmd=[]",
		"sam=[youzi$#1003]",
		"sam_only=[youzi$#1003]",
		"netapi_only=[]",
		"wmi_only=[]",
		"netcmd_only=[]",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected provider diagnostic output to contain %q, got %q", want, got)
		}
	}
}

func TestParseNetUserListOutputExtractsVisibleUsers(t *testing.T) {
	output := `
\\DESKTOP-NJIVMOJ 的用户帐户

-------------------------------------------------------------------------------
48967                    Administrator            DefaultAccount
Guest                    WDAGUtilityAccount
命令成功完成。
`

	got := parseNetUserListOutput(output)
	want := []string{"48967", "Administrator", "DefaultAccount", "Guest", "WDAGUtilityAccount"}
	if !slices.Equal(got, want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
	for _, blocked := range []string{"youzi$", "命令成功完成。"} {
		if slices.Contains(got, blocked) {
			t.Fatalf("did not expect %q in parsed users: %v", blocked, got)
		}
	}
}

func TestParseNetUserListOutputIgnoresMojibakeFooter(t *testing.T) {
	output := `
\\DESKTOP-NJIVMOJ 的用户帐户

-------------------------------------------------------------------------------
48967                    Administrator            DefaultAccount
Guest                    WDAGUtilityAccount
�����ɹ����ɡ�
`

	got := parseNetUserListOutput(output)
	want := []string{"48967", "Administrator", "DefaultAccount", "Guest", "WDAGUtilityAccount"}
	if !slices.Equal(got, want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
	for _, blocked := range []string{"�����ɹ����ɡ�"} {
		if slices.Contains(got, blocked) {
			t.Fatalf("did not expect %q in parsed users: %v", blocked, got)
		}
	}
}

func TestCorrelateAccountsSharedVDigestConfirmsShadow(t *testing.T) {
	ridA := uint32(1001)
	ridB := uint32(1003)
	accounts := correlateAccountSources(accountSourceBundle{
		SAM: []accountSourceRecord{
			{
				Username:     "48967",
				RID:          &ridA,
				Source:       accountSourceSAM,
				SAMRidKey:    true,
				SAMNameIndex: true,
				SAM: &models.SAMAccountEvidence{
					VDigest: "sha256:shared-v",
				},
			},
			{
				Username:     "youzi$",
				RID:          &ridB,
				Source:       accountSourceSAM,
				SAMRidKey:    true,
				SAMNameIndex: true,
				SAM: &models.SAMAccountEvidence{
					VDigest: "sha256:shared-v",
				},
			},
		},
	})

	var shadow *models.LocalUserAccount
	for i := range accounts {
		if accounts[i].Username == "youzi$" {
			shadow = &accounts[i]
			break
		}
	}
	if shadow == nil {
		t.Fatal("expected youzi$ account")
	}
	if !slices.Contains(shadow.Shadow.Reasons, shadowReasonSAMVShared) {
		t.Fatalf("expected %q in reasons, got %v", shadowReasonSAMVShared, shadow.Shadow.Reasons)
	}
}

func TestCorrelateAccountsBuiltinAdminAliasAndNetCommandInvisibleConfirmsShadow(t *testing.T) {
	sid := "S-1-5-21-1-2-3-1003"
	rid := uint32(1003)
	accounts := correlateAccountSources(accountSourceBundle{
		NetCmd: []accountSourceRecord{},
		SAM: []accountSourceRecord{
			{
				Username:     "youzi$",
				SID:          &sid,
				RID:          &rid,
				Source:       accountSourceSAM,
				SAMRidKey:    true,
				SAMNameIndex: true,
				SAM: &models.SAMAccountEvidence{
					BuiltinAliasMemberships: []string{"Administrators"},
				},
				SAMAliasMembership: true,
			},
		},
	})

	if len(accounts) != 1 {
		t.Fatalf("expected one account, got %d", len(accounts))
	}
	got := accounts[0]
	if !got.Shadow.IsShadowAccount {
		t.Fatalf("expected shadow account")
	}
	if !slices.Contains(got.Shadow.Reasons, shadowReasonAdminAliasMember) {
		t.Fatalf("expected %q in reasons %v", shadowReasonAdminAliasMember, got.Shadow.Reasons)
	}
}

func TestCorrelateAccountsSharedFDigestDoesNotMarkBuiltinAdministratorShadow(t *testing.T) {
	adminSID := "S-1-5-21-1-2-3-500"
	adminRID := uint32(500)
	shadowSID := "S-1-5-21-1-2-3-1003"
	shadowRID := uint32(1003)
	accounts := correlateAccountSources(accountSourceBundle{
		NetAPI: []accountSourceRecord{
			{Username: "Administrator", SID: &adminSID, RID: &adminRID, Source: accountSourceNetAPI},
		},
		WMI: []accountSourceRecord{
			{Username: "Administrator", SID: &adminSID, RID: &adminRID, Source: accountSourceWMI},
		},
		NetCmd: []accountSourceRecord{
			{Username: "Administrator", SID: &adminSID, RID: &adminRID, Source: accountSourceNetCmd},
		},
		SAM: []accountSourceRecord{
			{
				Username:     "Administrator",
				SID:          &adminSID,
				RID:          &adminRID,
				Source:       accountSourceSAM,
				SAMRidKey:    true,
				SAMNameIndex: true,
				NameIndexRID: &adminRID,
				SAM: &models.SAMAccountEvidence{
					FDigest: "sha256:shared-f",
				},
			},
			{
				Username:     "youzi$",
				SID:          &shadowSID,
				RID:          &shadowRID,
				Source:       accountSourceSAM,
				SAMRidKey:    true,
				SAMNameIndex: true,
				NameIndexRID: &shadowRID,
				SAM: &models.SAMAccountEvidence{
					FDigest: "sha256:shared-f",
				},
			},
		},
	})

	var admin, shadow *models.LocalUserAccount
	for i := range accounts {
		switch accounts[i].Username {
		case "Administrator":
			admin = &accounts[i]
		case "youzi$":
			shadow = &accounts[i]
		}
	}
	if admin == nil || shadow == nil {
		t.Fatalf("expected both Administrator and youzi$, got %#v", accounts)
	}
	if admin.Shadow.IsShadowAccount {
		t.Fatalf("expected builtin Administrator to stay non-shadow, got %+v", admin.Shadow)
	}
	if slices.Contains(admin.Shadow.Reasons, shadowReasonSAMFShared) {
		t.Fatalf("did not expect %q in Administrator reasons %v", shadowReasonSAMFShared, admin.Shadow.Reasons)
	}
	if !shadow.Shadow.IsShadowAccount {
		t.Fatalf("expected youzi$ to remain shadow, got %+v", shadow.Shadow)
	}
	if !slices.Contains(shadow.Shadow.Reasons, shadowReasonSAMFShared) {
		t.Fatalf("expected %q in youzi$ reasons %v", shadowReasonSAMFShared, shadow.Shadow.Reasons)
	}
}

func TestCorrelateAccountsBuiltinAdministratorAliasDoesNotConfirmShadow(t *testing.T) {
	sid := "S-1-5-21-1-2-3-500"
	rid := uint32(500)
	accounts := correlateAccountSources(accountSourceBundle{
		NetAPI: []accountSourceRecord{
			{Username: "Administrator", SID: &sid, RID: &rid, Source: accountSourceNetAPI},
		},
		WMI: []accountSourceRecord{
			{Username: "Administrator", SID: &sid, RID: &rid, Source: accountSourceWMI},
		},
		NetCmd: []accountSourceRecord{},
		SAM: []accountSourceRecord{
			{
				Username:     "Administrator",
				SID:          &sid,
				RID:          &rid,
				Source:       accountSourceSAM,
				SAMRidKey:    true,
				SAMNameIndex: true,
				NameIndexRID: &rid,
				SAM: &models.SAMAccountEvidence{
					BuiltinAliasMemberships: []string{"Administrators"},
				},
				SAMAliasMembership: true,
			},
		},
	})

	if len(accounts) != 1 {
		t.Fatalf("expected one account, got %d", len(accounts))
	}
	got := accounts[0]
	if got.Shadow.IsShadowAccount {
		t.Fatalf("expected builtin Administrator to stay non-shadow, got %+v", got.Shadow)
	}
	if slices.Contains(got.Shadow.Reasons, shadowReasonAdminAliasMember) {
		t.Fatalf("did not expect %q in reasons %v", shadowReasonAdminAliasMember, got.Shadow.Reasons)
	}
}
