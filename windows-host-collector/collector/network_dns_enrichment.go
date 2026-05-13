package collector

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"windows-host-collector/models"
)

type dnsResolver interface {
	LookupHost(context.Context, string) ([]string, error)
}

type dnsResolverFunc func(context.Context, string) ([]string, error)

func (fn dnsResolverFunc) LookupHost(ctx context.Context, host string) ([]string, error) {
	return fn(ctx, host)
}

type netDNSResolver struct{}

var defaultDNSResolver dnsResolver = netDNSResolver{}

func SetDNSResolverForTesting(resolver dnsResolver) func() {
	previous := defaultDNSResolver
	defaultDNSResolver = resolver
	return func() {
		defaultDNSResolver = previous
	}
}

func (netDNSResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	resolver := net.DefaultResolver
	return resolver.LookupHost(ctx, host)
}

func parseIPConfigDNSCache(output string) []models.DnsCacheRecord {
	type pendingRecord struct {
		host       string
		recordType string
		ipAddress  string
		ttl        int
	}

	var records []models.DnsCacheRecord
	current := pendingRecord{}
	flush := func() {
		if current.host == "" {
			return
		}
		records = append(records, models.DnsCacheRecord{
			ID:         fmt.Sprintf("dns-%d", len(records)),
			Host:       current.host,
			RecordType: current.recordType,
			IPAddress:  current.ipAddress,
			TTL:        current.ttl,
		})
		current = pendingRecord{}
	}

	for _, rawLine := range strings.Split(output, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}

		if value, ok := parseDNSLineValue(line, []string{"Record Name", "记录名称", "记录名"}); ok {
			flush()
			current.host = value
			continue
		}
		if current.host == "" {
			continue
		}
		if value, ok := parseDNSLineValue(line, []string{"Record Type", "记录类型"}); ok {
			current.recordType = dnsTypeNumberToString(value)
			continue
		}
		if value, ok := parseDNSLineValue(line, []string{"Time To Live", "TTL", "生存时间"}); ok {
			if ttl, err := strconv.Atoi(value); err == nil {
				current.ttl = ttl
			}
			continue
		}
		if value, ok := parseDNSLineValue(line, []string{"A (Host) Record", "A Record", "AAAA Record", "记录"}); ok && isIPAddress(value) {
			current.ipAddress = value
			if current.recordType == "" {
				current.recordType = dnsRecordTypeForIP(value)
			}
			continue
		}
	}
	flush()

	return records
}

func enrichDNSCacheRecords(
	ctx context.Context,
	records []models.DnsCacheRecord,
	history []models.BrowserHistoryEntry,
	resolver dnsResolver,
) []models.DnsCacheRecord {
	enriched := make([]models.DnsCacheRecord, 0, len(records))
	hostsWithIP := make(map[string]struct{})
	missingAddressRecords := make(map[string][]models.DnsCacheRecord)
	seenRecord := make(map[string]struct{})
	candidates := make([]string, 0)
	candidateSet := make(map[string]struct{})

	addCandidate := func(host string) {
		normalized := normalizeDNSHost(host)
		if normalized == "" {
			return
		}
		if _, ok := candidateSet[normalized]; ok {
			return
		}
		candidateSet[normalized] = struct{}{}
		candidates = append(candidates, normalized)
	}

	for _, record := range records {
		hostKey := normalizeDNSHost(record.Host)
		if hostKey == "" {
			continue
		}
		if !isIPAddress(record.IPAddress) && isResolvableDNSRecordType(record.RecordType) {
			missingAddressRecords[hostKey] = append(missingAddressRecords[hostKey], record)
			addCandidate(record.Host)
			continue
		}
		recordKey := hostKey + "\x00" + dnsRecordTypeForRecord(record) + "\x00" + record.IPAddress
		if _, ok := seenRecord[recordKey]; ok {
			continue
		}
		seenRecord[recordKey] = struct{}{}
		enriched = append(enriched, record)
		if isIPAddress(record.IPAddress) {
			hostsWithIP[hostKey] = struct{}{}
		}
		addCandidate(record.Host)
	}
	for _, entry := range history {
		addCandidate(browserHistoryHostname(entry.URL))
	}

	if resolver == nil {
		resolver = defaultDNSResolver
	}
	for _, host := range candidates {
		if _, ok := hostsWithIP[host]; ok {
			continue
		}
		ips, err := resolver.LookupHost(ctx, host)
		if err != nil {
			enriched = append(enriched, missingAddressRecords[host]...)
			continue
		}
		resolved := false
		for _, ip := range ips {
			if !isIPAddress(ip) {
				continue
			}
			resolved = true
			recordType := dnsRecordTypeForIP(ip)
			recordKey := host + "\x00" + recordType + "\x00" + ip
			if _, ok := seenRecord[recordKey]; ok {
				continue
			}
			seenRecord[recordKey] = struct{}{}
			enriched = append(enriched, models.DnsCacheRecord{
				ID:         fmt.Sprintf("dns-%d", len(enriched)),
				Host:       host,
				RecordType: recordType,
				IPAddress:  ip,
			})
		}
		if !resolved {
			enriched = append(enriched, missingAddressRecords[host]...)
		}
	}
	for i := range enriched {
		enriched[i].ID = fmt.Sprintf("dns-%d", i)
	}
	return enriched
}

func EnrichDNSCacheRecords(ctx context.Context, records []models.DnsCacheRecord, history []models.BrowserHistoryEntry) []models.DnsCacheRecord {
	return enrichDNSCacheRecords(ctx, records, history, nil)
}

func isResolvableDNSRecordType(recordType string) bool {
	switch strings.ToUpper(strings.TrimSpace(recordType)) {
	case "", "A", "AAAA":
		return true
	default:
		return false
	}
}

func browserHistoryHostname(rawURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return ""
	}
	host := parsed.Hostname()
	if host == "" || isIPAddress(host) {
		return ""
	}
	return normalizeDNSHost(host)
}

func normalizeDNSHost(host string) string {
	host = strings.TrimSpace(strings.TrimSuffix(host, "."))
	host = strings.ToLower(host)
	if host == "" || isIPAddress(host) {
		return ""
	}
	return host
}

func dnsRecordTypeForRecord(record models.DnsCacheRecord) string {
	if record.RecordType != "" {
		return record.RecordType
	}
	return dnsRecordTypeForIP(record.IPAddress)
}

func dnsRecordTypeForIP(ip string) string {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return ""
	}
	if parsed.To4() != nil {
		return "A"
	}
	return "AAAA"
}

func isIPAddress(value string) bool {
	return net.ParseIP(strings.TrimSpace(value)) != nil
}

func parseDNSLineValue(line string, labels []string) (string, bool) {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return "", false
	}

	left := normalizeDNSLabel(parts[0])
	right := strings.TrimSpace(parts[1])
	if right == "" {
		return "", false
	}

	for _, label := range labels {
		if left == normalizeDNSLabel(label) {
			return right, true
		}
	}

	return "", false
}

func normalizeDNSLabel(s string) string {
	s = strings.TrimSpace(s)
	replacer := strings.NewReplacer(
		" ", "",
		"\t", "",
		".", "",
		"。", "",
	)
	return strings.ToLower(replacer.Replace(s))
}

func dnsTypeNumberToString(t string) string {
	t = strings.TrimSpace(t)
	switch t {
	case "1":
		return "A"
	case "2":
		return "NS"
	case "5":
		return "CNAME"
	case "6":
		return "SOA"
	case "12":
		return "PTR"
	case "15":
		return "MX"
	case "16":
		return "TXT"
	case "28":
		return "AAAA"
	case "33":
		return "SRV"
	default:
		return t
	}
}
