package collector

import "testing"

func TestParseEventXMLExtractsStructuredFieldsForFailedLogon(t *testing.T) {
	xmlStr := `<Event>
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"></Provider>
    <EventID>4625</EventID>
    <Level>0</Level>
    <TimeCreated SystemTime="2026-04-28T08:00:00.0000000Z"></TimeCreated>
    <Computer>host-1</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-0-0</Data>
    <Data Name="SubjectUserName">-</Data>
    <Data Name="SubjectDomainName">-</Data>
    <Data Name="TargetUserSid">S-1-0-0</Data>
    <Data Name="TargetUserName">alice</Data>
    <Data Name="TargetDomainName">CONTOSO</Data>
    <Data Name="Status">0xC000006D</Data>
    <Data Name="SubStatus">0xC000006A</Data>
    <Data Name="FailureReason">%%2313</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="ProcessName">C:\Windows\System32\lsass.exe</Data>
    <Data Name="IpAddress">10.0.0.25</Data>
    <Data Name="IpPort">51123</Data>
    <Data Name="WorkstationName">WKSTN-01</Data>
  </EventData>
</Event>`

	entry := parseEventXML(xmlStr, "security", 0)
	if entry == nil {
		t.Fatal("expected parsed event")
	}
	if entry.EventID != 4625 {
		t.Fatalf("expected eventId 4625, got %d", entry.EventID)
	}
	if entry.LogonType == nil || *entry.LogonType != 3 {
		t.Fatalf("expected logonType 3, got %#v", entry.LogonType)
	}
	if entry.ProcessName == nil || *entry.ProcessName != `C:\Windows\System32\lsass.exe` {
		t.Fatalf("expected processName to be extracted, got %#v", entry.ProcessName)
	}
	if got := entry.EventData["TargetUserName"]; got != "alice" {
		t.Fatalf("expected TargetUserName alice, got %q", got)
	}
	if got := entry.EventData["Status"]; got != "0xC000006D" {
		t.Fatalf("expected Status 0xC000006D, got %q", got)
	}
	if got := entry.NormalizedFields["accountName"]; got != "alice" {
		t.Fatalf("expected normalized accountName alice, got %q", got)
	}
	if got := entry.NormalizedFields["accountDomain"]; got != "CONTOSO" {
		t.Fatalf("expected normalized accountDomain CONTOSO, got %q", got)
	}
	if got := entry.NormalizedFields["securityId"]; got != "S-1-0-0" {
		t.Fatalf("expected normalized securityId S-1-0-0, got %q", got)
	}
	if got := entry.NormalizedFields["status"]; got != "0xC000006D" {
		t.Fatalf("expected normalized status 0xC000006D, got %q", got)
	}
	if got := entry.NormalizedFields["subStatus"]; got != "0xC000006A" {
		t.Fatalf("expected normalized subStatus 0xC000006A, got %q", got)
	}
	if got := entry.NormalizedFields["failureReason"]; got != "%%2313" {
		t.Fatalf("expected normalized failureReason %%2313, got %q", got)
	}
	if got := entry.NormalizedFields["ipAddress"]; got != "10.0.0.25" {
		t.Fatalf("expected normalized ipAddress 10.0.0.25, got %q", got)
	}
	if len(entry.Keywords) == 0 {
		t.Fatal("expected keywords to be populated")
	}
}

func TestParseEventXMLExtractsStructuredFieldsForProcessCreation(t *testing.T) {
	xmlStr := `<Event>
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"></Provider>
    <EventID>4688</EventID>
    <Level>0</Level>
    <TimeCreated SystemTime="2026-04-28T08:05:00.0000000Z"></TimeCreated>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-18</Data>
    <Data Name="SubjectUserName">SYSTEM</Data>
    <Data Name="SubjectDomainName">NT AUTHORITY</Data>
    <Data Name="NewProcessId">0x1f4</Data>
    <Data Name="NewProcessName">C:\Windows\System32\cmd.exe</Data>
    <Data Name="TokenElevationType">%%1936</Data>
    <Data Name="ProcessCommandLine">cmd.exe /c whoami</Data>
    <Data Name="ParentProcessName">C:\Windows\explorer.exe</Data>
    <Data Name="MandatoryLabel">S-1-16-12288</Data>
  </EventData>
</Event>`

	entry := parseEventXML(xmlStr, "security", 0)
	if entry == nil {
		t.Fatal("expected parsed event")
	}
	if got := entry.NormalizedFields["actorAccountName"]; got != "SYSTEM" {
		t.Fatalf("expected actorAccountName SYSTEM, got %q", got)
	}
	if got := entry.NormalizedFields["actorAccountDomain"]; got != "NT AUTHORITY" {
		t.Fatalf("expected actorAccountDomain NT AUTHORITY, got %q", got)
	}
	if got := entry.NormalizedFields["newProcessName"]; got != `C:\Windows\System32\cmd.exe` {
		t.Fatalf("expected newProcessName cmd.exe, got %q", got)
	}
	if got := entry.NormalizedFields["commandLine"]; got != "cmd.exe /c whoami" {
		t.Fatalf("expected commandLine, got %q", got)
	}
	if got := entry.NormalizedFields["parentProcessName"]; got != `C:\Windows\explorer.exe` {
		t.Fatalf("expected parentProcessName explorer.exe, got %q", got)
	}
	if got := entry.NormalizedFields["tokenElevationType"]; got != "%%1936" {
		t.Fatalf("expected tokenElevationType %%1936, got %q", got)
	}
}

func TestParseEventXMLExtractsStructuredFieldsForUserCreation(t *testing.T) {
	xmlStr := `<Event>
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"></Provider>
    <EventID>4720</EventID>
    <Level>0</Level>
    <TimeCreated SystemTime="2026-04-28T08:10:00.0000000Z"></TimeCreated>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-1000</Data>
    <Data Name="SubjectUserName">admin</Data>
    <Data Name="SubjectDomainName">CONTOSO</Data>
    <Data Name="TargetUserName">alice</Data>
    <Data Name="TargetDomainName">CONTOSO</Data>
    <Data Name="TargetSid">S-1-5-21-2000</Data>
    <Data Name="SamAccountName">alice</Data>
    <Data Name="DisplayName">Alice Example</Data>
    <Data Name="UserPrincipalName">alice@contoso.local</Data>
    <Data Name="HomeDirectory">C:\Users\alice</Data>
  </EventData>
</Event>`

	entry := parseEventXML(xmlStr, "security", 0)
	if entry == nil {
		t.Fatal("expected parsed event")
	}
	if got := entry.NormalizedFields["actorAccountName"]; got != "admin" {
		t.Fatalf("expected actorAccountName admin, got %q", got)
	}
	if got := entry.NormalizedFields["targetAccountName"]; got != "alice" {
		t.Fatalf("expected targetAccountName alice, got %q", got)
	}
	if got := entry.NormalizedFields["targetSecurityId"]; got != "S-1-5-21-2000" {
		t.Fatalf("expected targetSecurityId, got %q", got)
	}
	if got := entry.NormalizedFields["samAccountName"]; got != "alice" {
		t.Fatalf("expected samAccountName alice, got %q", got)
	}
	if got := entry.NormalizedFields["userPrincipalName"]; got != "alice@contoso.local" {
		t.Fatalf("expected userPrincipalName, got %q", got)
	}
}

func TestParseEventXMLExtractsStructuredFieldsForKerberosPreAuthFailure(t *testing.T) {
	xmlStr := `<Event>
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"></Provider>
    <EventID>4771</EventID>
    <Level>0</Level>
    <TimeCreated SystemTime="2026-04-28T08:15:00.0000000Z"></TimeCreated>
  </System>
  <EventData>
    <Data Name="TargetUserName">alice</Data>
    <Data Name="TargetSid">S-1-0-0</Data>
    <Data Name="ServiceName">krbtgt/CONTOSO.LOCAL</Data>
    <Data Name="TicketOptions">0x40810010</Data>
    <Data Name="Status">0x18</Data>
    <Data Name="PreAuthType">2</Data>
    <Data Name="IpAddress">10.0.0.25</Data>
    <Data Name="IpPort">51123</Data>
  </EventData>
</Event>`

	entry := parseEventXML(xmlStr, "security", 0)
	if entry == nil {
		t.Fatal("expected parsed event")
	}
	if got := entry.NormalizedFields["targetAccountName"]; got != "alice" {
		t.Fatalf("expected targetAccountName alice, got %q", got)
	}
	if got := entry.NormalizedFields["serviceName"]; got != "krbtgt/CONTOSO.LOCAL" {
		t.Fatalf("expected serviceName, got %q", got)
	}
	if got := entry.NormalizedFields["ticketOptions"]; got != "0x40810010" {
		t.Fatalf("expected ticketOptions, got %q", got)
	}
	if got := entry.NormalizedFields["preAuthType"]; got != "2" {
		t.Fatalf("expected preAuthType 2, got %q", got)
	}
	if got := entry.NormalizedFields["status"]; got != "0x18" {
		t.Fatalf("expected status 0x18, got %q", got)
	}
}
