package collector

import (
	"context"
	"reflect"
	"testing"
	"windows-host-collector/models"
)

func TestParseIPConfigDNSCacheIncludesIPAddressAndTTL(t *testing.T) {
	output := `
Windows IP Configuration

    example.com
    ----------------------------------------
    Record Name . . . . . : example.com
    Record Type . . . . . : 1
    Time To Live  . . . . : 123
    Data Length . . . . . : 4
    Section . . . . . . . : Answer
    A (Host) Record . . . : 93.184.216.34

    ipv6.example.com
    ----------------------------------------
    Record Name . . . . . : ipv6.example.com
    Record Type . . . . . : 28
    Time To Live  . . . . : 456
    AAAA Record . . . . . : 2001:db8::10
`

	records := parseIPConfigDNSCache(output)
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d: %#v", len(records), records)
	}

	if records[0].Host != "example.com" || records[0].RecordType != "A" || records[0].IPAddress != "93.184.216.34" || records[0].TTL != 123 {
		t.Fatalf("unexpected A record: %#v", records[0])
	}
	if records[1].Host != "ipv6.example.com" || records[1].RecordType != "AAAA" || records[1].IPAddress != "2001:db8::10" || records[1].TTL != 456 {
		t.Fatalf("unexpected AAAA record: %#v", records[1])
	}
}

func TestMergeDNSCacheWithBrowserHistoryDomainsDedupesAndResolvesMissingIPs(t *testing.T) {
	existing := []models.DnsCacheRecord{
		{ID: "dns-0", Host: "Example.COM", RecordType: "A", IPAddress: "93.184.216.34", TTL: 60},
		{ID: "dns-1", Host: "missing.example.com", RecordType: "A"},
		{ID: "dns-2", Host: "alias.example.com", RecordType: "CNAME"},
	}
	history := []models.BrowserHistoryEntry{
		{URL: "https://missing.example.com/path"},
		{URL: "https://browser.example.com/search?q=1"},
		{URL: "https://EXAMPLE.com/again"},
		{URL: "file:///C:/temp/local-file.txt"},
		{URL: "http://192.168.1.10/admin"},
	}
	resolver := dnsResolverFunc(func(ctx context.Context, host string) ([]string, error) {
		switch host {
		case "missing.example.com":
			return []string{"203.0.113.10"}, nil
		case "browser.example.com":
			return []string{"198.51.100.7", "2001:db8::7"}, nil
		case "alias.example.com":
			return []string{"203.0.113.11"}, nil
		default:
			t.Fatalf("unexpected resolver host %q", host)
			return nil, nil
		}
	})

	records := enrichDNSCacheRecords(context.Background(), existing, history, resolver)
	got := make([]string, 0, len(records))
	for _, record := range records {
		got = append(got, record.Host+"|"+record.RecordType+"|"+record.IPAddress)
	}
	want := []string{
		"Example.COM|A|93.184.216.34",
		"alias.example.com|CNAME|",
		"missing.example.com|A|203.0.113.10",
		"alias.example.com|A|203.0.113.11",
		"browser.example.com|A|198.51.100.7",
		"browser.example.com|AAAA|2001:db8::7",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected records:\n got %#v\nwant %#v", got, want)
	}
}
