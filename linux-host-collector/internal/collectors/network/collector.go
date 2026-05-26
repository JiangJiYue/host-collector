package network

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type Result struct {
	Connections   []Connection   `json:"connections"`
	DNSCache      []DNSRecord    `json:"dnsCache,omitempty"`
	Hosts         []HostEntry    `json:"hosts,omitempty"`
	Routes        []Route        `json:"routes,omitempty"`
	Neighbors     []Neighbor     `json:"neighbors,omitempty"`
	FirewallRules []FirewallRule `json:"firewallRules,omitempty"`
	PolicyRules   []PolicyRule   `json:"policyRules,omitempty"`
	Sources       []string       `json:"sources"`
}

type Connection struct {
	Protocol      string `json:"protocol"`
	LocalAddress  string `json:"localAddress"`
	LocalPort     int    `json:"localPort"`
	RemoteAddress string `json:"remoteAddress"`
	RemotePort    int    `json:"remotePort"`
	State         string `json:"state"`
	Listen        bool   `json:"listen"`
	Inode         string `json:"inode,omitempty"`
}

type DNSRecord struct {
	Host       string `json:"host"`
	RecordType string `json:"recordType"`
	IPAddress  string `json:"ipAddress"`
	TTL        int    `json:"ttl,omitempty"`
	Source     string `json:"source,omitempty"`
	SourceType string `json:"sourceType,omitempty"`
}

type HostEntry struct {
	IPAddress string `json:"ipAddress"`
	Domain    string `json:"domain"`
}

type Route struct {
	Interface    string `json:"interface"`
	Destination  string `json:"destination"`
	Gateway      string `json:"gateway"`
	Mask         string `json:"mask"`
	Flags        string `json:"flags"`
	Metric       int    `json:"metric,omitempty"`
	DefaultRoute bool   `json:"defaultRoute"`
	Source       string `json:"source,omitempty"`
	SourceType   string `json:"sourceType,omitempty"`
}

type Neighbor struct {
	IPAddress  string `json:"ipAddress"`
	MACAddress string `json:"macAddress"`
	Interface  string `json:"interface"`
	State      string `json:"state,omitempty"`
	Flags      string `json:"flags,omitempty"`
}

type FirewallRule struct {
	Source          string   `json:"source"`
	Family          string   `json:"family,omitempty"`
	Table           string   `json:"table,omitempty"`
	Chain           string   `json:"chain,omitempty"`
	Action          string   `json:"action,omitempty"`
	Protocol        string   `json:"protocol,omitempty"`
	SourceCIDR      string   `json:"sourceCidr,omitempty"`
	DestinationCIDR string   `json:"destinationCidr,omitempty"`
	SourcePort      string   `json:"sourcePort,omitempty"`
	DestinationPort string   `json:"destinationPort,omitempty"`
	Raw             string   `json:"raw"`
	RiskTags        []string `json:"riskTags,omitempty"`
	SourceType      string   `json:"sourceType,omitempty"`
}

type PolicyRule struct {
	Source     string `json:"source"`
	Priority   string `json:"priority,omitempty"`
	From       string `json:"from,omitempty"`
	To         string `json:"to,omitempty"`
	Table      string `json:"table,omitempty"`
	Raw        string `json:"raw"`
	SourceType string `json:"sourceType,omitempty"`
}

func Collect(root string) (Result, error) {
	procNetRoot := filepath.Join(root, "proc", "net")
	files := []struct {
		name     string
		protocol string
	}{
		{name: "tcp", protocol: "tcp"},
		{name: "tcp6", protocol: "tcp6"},
		{name: "udp", protocol: "udp"},
		{name: "udp6", protocol: "udp6"},
	}

	var result Result
	for _, file := range files {
		connections, err := readProcNet(filepath.Join(procNetRoot, file.name), file.protocol)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return Result{}, err
		}
		result.Sources = append(result.Sources, filepath.Join("proc", "net", file.name))
		result.Connections = append(result.Connections, connections...)
	}
	if dnsRecords, err := readDNSRecords(filepath.Join(root, "etc", "resolv.conf")); err == nil && len(dnsRecords) > 0 {
		result.DNSCache = append(result.DNSCache, dnsRecords...)
		result.Sources = append(result.Sources, filepath.Join("etc", "resolv.conf"))
	}
	if hostEntries, err := readHostsEntries(filepath.Join(root, "etc", "hosts")); err == nil && len(hostEntries) > 0 {
		result.Hosts = append(result.Hosts, hostEntries...)
		result.Sources = append(result.Sources, filepath.Join("etc", "hosts"))
	}
	if routes, err := readRoutes(filepath.Join(root, "proc", "net", "route")); err == nil && len(routes) > 0 {
		result.Routes = append(result.Routes, routes...)
		result.Sources = append(result.Sources, filepath.Join("proc", "net", "route"))
	}
	if neighbors, err := readARPNeighbors(filepath.Join(root, "proc", "net", "arp")); err == nil && len(neighbors) > 0 {
		result.Neighbors = append(result.Neighbors, neighbors...)
		result.Sources = append(result.Sources, filepath.Join("proc", "net", "arp"))
	}
	for _, candidate := range []struct {
		relPath string
		family  string
	}{
		{relPath: filepath.Join("etc", "iptables", "rules.v4"), family: "ipv4"},
		{relPath: filepath.Join("etc", "iptables", "rules.v6"), family: "ipv6"},
	} {
		if rules, err := readIPTablesRules(filepath.Join(root, candidate.relPath), candidate.relPath, candidate.family, "persistent_config"); err == nil && len(rules) > 0 {
			result.FirewallRules = append(result.FirewallRules, rules...)
			result.Sources = append(result.Sources, candidate.relPath)
		}
	}
	for _, candidate := range []struct {
		relPath string
		family  string
	}{
		{relPath: filepath.Join("run", "host-collector", "runtime", "iptables-save.v4"), family: "ipv4"},
		{relPath: filepath.Join("run", "host-collector", "runtime", "iptables-save.v6"), family: "ipv6"},
	} {
		if rules, err := readIPTablesRules(filepath.Join(root, candidate.relPath), candidate.relPath, candidate.family, "runtime"); err == nil && len(rules) > 0 {
			result.FirewallRules = append(result.FirewallRules, rules...)
			result.Sources = append(result.Sources, candidate.relPath)
		}
	}
	if rules, err := readNFTRules(filepath.Join(root, "run", "host-collector", "runtime", "nft-list-ruleset.txt"), filepath.Join("run", "host-collector", "runtime", "nft-list-ruleset.txt")); err == nil && len(rules) > 0 {
		result.FirewallRules = append(result.FirewallRules, rules...)
		result.Sources = append(result.Sources, filepath.Join("run", "host-collector", "runtime", "nft-list-ruleset.txt"))
	}
	for _, relPath := range []string{
		filepath.Join("etc", "iproute2", "rules.v4"),
		filepath.Join("etc", "iproute2", "rules.v6"),
	} {
		if rules, err := readPolicyRules(filepath.Join(root, relPath), relPath, "persistent_config"); err == nil && len(rules) > 0 {
			result.PolicyRules = append(result.PolicyRules, rules...)
			result.Sources = append(result.Sources, relPath)
		}
	}
	if routes, err := readRuntimeRoutes(filepath.Join(root, "run", "host-collector", "runtime", "ip-route.txt"), filepath.Join("run", "host-collector", "runtime", "ip-route.txt")); err == nil && len(routes) > 0 {
		result.Routes = append(result.Routes, routes...)
		result.Sources = append(result.Sources, filepath.Join("run", "host-collector", "runtime", "ip-route.txt"))
	}
	if rules, err := readPolicyRules(filepath.Join(root, "run", "host-collector", "runtime", "ip-rule.txt"), filepath.Join("run", "host-collector", "runtime", "ip-rule.txt"), "runtime"); err == nil && len(rules) > 0 {
		result.PolicyRules = append(result.PolicyRules, rules...)
		result.Sources = append(result.Sources, filepath.Join("run", "host-collector", "runtime", "ip-rule.txt"))
	}
	for _, relPath := range []string{
		filepath.Join("run", "systemd", "resolve", "cache.txt"),
		filepath.Join("var", "lib", "misc", "dnsmasq.leases"),
	} {
		if records, err := readRuntimeDNSRecords(filepath.Join(root, relPath), relPath); err == nil && len(records) > 0 {
			result.DNSCache = append(result.DNSCache, records...)
			result.Sources = append(result.Sources, relPath)
		}
	}
	sort.Strings(result.Sources)
	sort.Slice(result.Connections, func(i, j int) bool {
		left := result.Connections[i]
		right := result.Connections[j]
		return connectionSortKey(left) < connectionSortKey(right)
	})
	sort.Slice(result.Routes, func(i, j int) bool {
		left := result.Routes[i]
		right := result.Routes[j]
		return left.Interface+"|"+left.Destination+"|"+left.Gateway < right.Interface+"|"+right.Destination+"|"+right.Gateway
	})
	sort.Slice(result.Neighbors, func(i, j int) bool {
		left := result.Neighbors[i]
		right := result.Neighbors[j]
		return left.Interface+"|"+left.IPAddress+"|"+left.MACAddress < right.Interface+"|"+right.IPAddress+"|"+right.MACAddress
	})
	sort.Slice(result.FirewallRules, func(i, j int) bool {
		left := result.FirewallRules[i]
		right := result.FirewallRules[j]
		return left.Source+"|"+left.Table+"|"+left.Chain+"|"+left.Action+"|"+left.Raw < right.Source+"|"+right.Table+"|"+right.Chain+"|"+right.Action+"|"+right.Raw
	})
	sort.Slice(result.PolicyRules, func(i, j int) bool {
		left := result.PolicyRules[i]
		right := result.PolicyRules[j]
		return left.Source+"|"+left.Priority+"|"+left.Raw < right.Source+"|"+right.Priority+"|"+right.Raw
	})
	return result, nil
}

func readIPTablesRules(path string, source string, family string, sourceType string) ([]FirewallRule, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	table := ""
	var rules []FirewallRule
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "*") {
			table = strings.TrimPrefix(line, "*")
			continue
		}
		if !strings.HasPrefix(line, "-A ") {
			continue
		}
		rules = append(rules, parseIPTablesRule(source, family, table, line, sourceType))
	}
	return rules, scanner.Err()
}

func parseIPTablesRule(source string, family string, table string, line string, sourceType string) FirewallRule {
	fields := strings.Fields(line)
	rule := FirewallRule{Source: source, Family: family, Table: table, Raw: line, SourceType: sourceType}
	if len(fields) >= 2 {
		rule.Chain = fields[1]
	}
	for index := 2; index < len(fields); index++ {
		field := fields[index]
		value := func() string {
			if index+1 >= len(fields) {
				return ""
			}
			index++
			return fields[index]
		}
		switch field {
		case "-p":
			rule.Protocol = value()
		case "-s":
			rule.SourceCIDR = value()
		case "-d":
			rule.DestinationCIDR = value()
		case "--sport":
			rule.SourcePort = value()
		case "--dport":
			rule.DestinationPort = value()
		case "-j":
			rule.Action = value()
		}
	}
	rule.RiskTags = firewallRiskTags(rule)
	return rule
}

func readNFTRules(path string, source string) ([]FirewallRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rules []FirewallRule
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		rule := FirewallRule{Source: source, SourceType: "runtime", Raw: line, Family: "inet"}
		fields := strings.Fields(strings.NewReplacer("{", " ", "}", " ", ";", " ").Replace(line))
		for index, field := range fields {
			switch field {
			case "table":
				if index+2 < len(fields) {
					rule.Family = fields[index+1]
					rule.Table = fields[index+2]
				}
			case "chain":
				if index+1 < len(fields) {
					rule.Chain = fields[index+1]
				}
			case "tcp", "udp":
				rule.Protocol = field
				if index+2 < len(fields) && fields[index+1] == "dport" {
					rule.DestinationPort = fields[index+2]
				}
			case "accept", "drop", "reject":
				rule.Action = field
			}
		}
		rule.RiskTags = firewallRiskTags(rule)
		rules = append(rules, rule)
	}
	return rules, nil
}

func firewallRiskTags(rule FirewallRule) []string {
	var tags []string
	switch strings.ToUpper(rule.Action) {
	case "DROP", "REJECT":
		tags = append(tags, "drop_rule")
	case "ACCEPT":
		tags = append(tags, "accept_rule")
	}
	if rule.DestinationPort == "22" {
		tags = append(tags, "ssh_exposure")
	}
	if rule.DestinationCIDR != "" && rule.DestinationCIDR != "0.0.0.0/0" {
		tags = append(tags, "external_destination_rule")
	}
	return uniqueStrings(tags)
}

func readPolicyRules(path string, source string, sourceType string) ([]PolicyRule, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var rules []PolicyRule
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rules = append(rules, parsePolicyRule(source, line, sourceType))
	}
	return rules, scanner.Err()
}

func parsePolicyRule(source string, line string, sourceType string) PolicyRule {
	rule := PolicyRule{Source: source, Raw: line, SourceType: sourceType}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return rule
	}
	if strings.HasSuffix(fields[0], ":") {
		rule.Priority = strings.TrimSuffix(fields[0], ":")
		fields = fields[1:]
	}
	for index := 0; index < len(fields); index++ {
		if index+1 >= len(fields) {
			break
		}
		switch fields[index] {
		case "from":
			index++
			rule.From = fields[index]
		case "to":
			index++
			rule.To = fields[index]
		case "lookup", "table":
			index++
			rule.Table = fields[index]
		}
	}
	return rule
}

func readRuntimeRoutes(path string, source string) ([]Route, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var routes []Route
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		route := Route{Source: source, SourceType: "runtime", Destination: firstField(line)}
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == "default" {
			route.Destination = "0.0.0.0/0"
			route.DefaultRoute = true
		}
		for index := 0; index < len(fields); index++ {
			if index+1 >= len(fields) {
				break
			}
			switch fields[index] {
			case "via":
				index++
				route.Gateway = fields[index]
			case "dev":
				index++
				route.Interface = fields[index]
			case "metric":
				index++
				route.Metric, _ = strconv.Atoi(fields[index])
			}
		}
		routes = append(routes, route)
	}
	return routes, scanner.Err()
}

func readRuntimeDNSRecords(path string, source string) ([]DNSRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var records []DNSRecord
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 0 {
			continue
		}
		if strings.HasSuffix(source, "dnsmasq.leases") && len(fields) >= 4 {
			records = append(records, DNSRecord{Host: fields[3], RecordType: "lease", IPAddress: fields[2], Source: source, SourceType: "runtime"})
			continue
		}
		if len(fields) >= 3 && net.ParseIP(fields[2]) != nil {
			ttl := 0
			for _, field := range fields[3:] {
				if value, ok := strings.CutPrefix(field, "ttl="); ok {
					ttl, _ = strconv.Atoi(value)
				}
			}
			records = append(records, DNSRecord{Host: fields[0], RecordType: fields[1], IPAddress: fields[2], TTL: ttl, Source: source, SourceType: "runtime"})
		}
	}
	return records, nil
}

func firstField(line string) string {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func readRoutes(path string) ([]Route, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var routes []Route
	scanner := bufio.NewScanner(file)
	firstLine := true
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if firstLine {
			firstLine = false
			continue
		}
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		destination, err := parseRouteIPv4Hex(fields[1])
		if err != nil {
			continue
		}
		gateway, err := parseRouteIPv4Hex(fields[2])
		if err != nil {
			continue
		}
		mask, err := parseRouteIPv4Hex(fields[7])
		if err != nil {
			continue
		}
		metric, _ := strconv.Atoi(fields[6])
		routes = append(routes, Route{
			Interface:    fields[0],
			Destination:  destination,
			Gateway:      gateway,
			Mask:         mask,
			Flags:        fields[3],
			Metric:       metric,
			DefaultRoute: destination == "0.0.0.0" && mask == "0.0.0.0",
		})
	}
	return routes, scanner.Err()
}

func readARPNeighbors(path string) ([]Neighbor, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var neighbors []Neighbor
	scanner := bufio.NewScanner(file)
	firstLine := true
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if firstLine {
			firstLine = false
			continue
		}
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		neighbors = append(neighbors, Neighbor{
			IPAddress:  fields[0],
			MACAddress: strings.ToLower(fields[3]),
			Interface:  fields[5],
			State:      arpState(fields[2]),
			Flags:      fields[2],
		})
	}
	return neighbors, scanner.Err()
}

func parseRouteIPv4Hex(value string) (string, error) {
	if len(value) != 8 {
		return "", fmt.Errorf("invalid route ipv4 hex")
	}
	data, err := hex.DecodeString(value)
	if err != nil {
		return "", err
	}
	reverse(data)
	return net.IPv4(data[0], data[1], data[2], data[3]).String(), nil
}

func arpState(flags string) string {
	value, err := strconv.ParseInt(strings.TrimPrefix(strings.ToLower(flags), "0x"), 16, 64)
	if err != nil {
		return ""
	}
	if value&0x2 != 0 {
		return "reachable"
	}
	return "incomplete"
}

func readDNSRecords(path string) ([]DNSRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var records []DNSRecord
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		records = append(records, DNSRecord{
			Host:       "nameserver",
			RecordType: "nameserver",
			IPAddress:  fields[1],
		})
	}
	return records, nil
}

func readHostsEntries(path string) ([]HostEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var entries []HostEntry
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 2 {
			continue
		}
		ip := fields[0]
		for _, domain := range fields[1:] {
			entries = append(entries, HostEntry{IPAddress: ip, Domain: domain})
		}
	}
	return entries, nil
}

func readProcNet(path string, protocol string) ([]Connection, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var connections []Connection
	scanner := bufio.NewScanner(file)
	firstLine := true
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if firstLine {
			firstLine = false
			continue
		}
		if line == "" {
			continue
		}
		connection, err := parseSocketLine(line, protocol)
		if err != nil {
			continue
		}
		connections = append(connections, connection)
	}
	return connections, scanner.Err()
}

func parseSocketLine(line string, protocol string) (Connection, error) {
	fields := strings.Fields(line)
	if len(fields) < 10 {
		return Connection{}, fmt.Errorf("malformed proc net row")
	}
	localAddress, localPort, err := parseEndpoint(fields[1], strings.HasSuffix(protocol, "6"))
	if err != nil {
		return Connection{}, err
	}
	remoteAddress, remotePort, err := parseEndpoint(fields[2], strings.HasSuffix(protocol, "6"))
	if err != nil {
		return Connection{}, err
	}
	state := socketState(protocol, fields[3])
	return Connection{
		Protocol:      protocol,
		LocalAddress:  localAddress,
		LocalPort:     localPort,
		RemoteAddress: remoteAddress,
		RemotePort:    remotePort,
		State:         state,
		Listen:        state == "LISTEN",
		Inode:         fields[9],
	}, nil
}

func parseEndpoint(value string, ipv6 bool) (string, int, error) {
	addressHex, portHex, ok := strings.Cut(value, ":")
	if !ok {
		return "", 0, fmt.Errorf("malformed endpoint")
	}
	port64, err := strconv.ParseInt(portHex, 16, 32)
	if err != nil {
		return "", 0, err
	}
	address, err := parseAddress(addressHex, ipv6)
	if err != nil {
		return "", 0, err
	}
	return address, int(port64), nil
}

func parseAddress(value string, ipv6 bool) (string, error) {
	data, err := hex.DecodeString(value)
	if err != nil {
		return "", err
	}
	if ipv6 {
		if len(data) != net.IPv6len {
			return "", fmt.Errorf("invalid ipv6 address length")
		}
		for offset := 0; offset < len(data); offset += 4 {
			reverse(data[offset : offset+4])
		}
		return net.IP(data).String(), nil
	}
	if len(data) != net.IPv4len {
		return "", fmt.Errorf("invalid ipv4 address length")
	}
	reverse(data)
	return net.IPv4(data[0], data[1], data[2], data[3]).String(), nil
}

func socketState(protocol string, state string) string {
	if strings.HasPrefix(protocol, "udp") {
		return "UDP"
	}
	states := map[string]string{
		"01": "ESTABLISHED",
		"02": "SYN_SENT",
		"03": "SYN_RECV",
		"04": "FIN_WAIT1",
		"05": "FIN_WAIT2",
		"06": "TIME_WAIT",
		"07": "CLOSE",
		"08": "CLOSE_WAIT",
		"09": "LAST_ACK",
		"0A": "LISTEN",
		"0B": "CLOSING",
	}
	upper := strings.ToUpper(state)
	if name, ok := states[upper]; ok {
		return name
	}
	return upper
}

func reverse(data []byte) {
	for left, right := 0, len(data)-1; left < right; left, right = left+1, right-1 {
		data[left], data[right] = data[right], data[left]
	}
}

func connectionSortKey(connection Connection) string {
	return fmt.Sprintf("%s|%s|%05d|%s|%05d|%s", connection.Protocol, connection.LocalAddress, connection.LocalPort, connection.RemoteAddress, connection.RemotePort, connection.Inode)
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	var result []string
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
