package network

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCollectParsesProcNetTCPAndUDP(t *testing.T) {
	result, err := Collect(filepath.Join("..", "testdata", "root"))
	if err != nil {
		t.Fatalf("collect network: %v", err)
	}
	for _, source := range []string{"proc/net/tcp", "proc/net/udp", "proc/net/route", "proc/net/arp", "etc/resolv.conf", "etc/hosts", "etc/iptables/rules.v4", "etc/iproute2/rules.v4"} {
		if !containsString(result.Sources, source) {
			t.Fatalf("expected source %s in %#v", source, result.Sources)
		}
	}
	if len(result.Connections) != 4 {
		t.Fatalf("expected four connections, got %#v", result.Connections)
	}
	if len(result.DNSCache) != 2 {
		t.Fatalf("expected two dns cache records, got %#v", result.DNSCache)
	}
	if len(result.Hosts) != 3 {
		t.Fatalf("expected three hosts entries, got %#v", result.Hosts)
	}
	if len(result.Routes) != 2 {
		t.Fatalf("expected two route entries, got %#v", result.Routes)
	}
	if len(result.Neighbors) != 1 {
		t.Fatalf("expected one neighbor entry, got %#v", result.Neighbors)
	}
	if len(result.FirewallRules) != 2 {
		t.Fatalf("expected two firewall rules, got %#v", result.FirewallRules)
	}
	if len(result.PolicyRules) != 1 {
		t.Fatalf("expected one policy rule, got %#v", result.PolicyRules)
	}

	listen := findConnection(t, result.Connections, "tcp", "12345")
	if listen.Protocol != "tcp" || listen.LocalAddress != "127.0.0.1" || listen.LocalPort != 8080 {
		t.Fatalf("unexpected listen socket: %#v", listen)
	}
	if listen.RemoteAddress != "0.0.0.0" || listen.RemotePort != 0 || listen.State != "LISTEN" || !listen.Listen || listen.Inode != "12345" {
		t.Fatalf("unexpected listen socket details: %#v", listen)
	}

	established := findConnection(t, result.Connections, "tcp", "67890")
	if established.Protocol != "tcp" || established.LocalAddress != "10.0.0.2" || established.LocalPort != 80 {
		t.Fatalf("unexpected established socket local endpoint: %#v", established)
	}
	if established.RemoteAddress != "8.8.8.8" || established.RemotePort != 443 || established.State != "ESTABLISHED" || established.Listen {
		t.Fatalf("unexpected established socket details: %#v", established)
	}

	processConnection := findConnection(t, result.Connections, "tcp", "7001")
	if processConnection.LocalAddress != "10.0.0.2" || processConnection.LocalPort != 6000 || processConnection.RemoteAddress != "10.0.0.5" || processConnection.RemotePort != 443 {
		t.Fatalf("unexpected process socket details: %#v", processConnection)
	}

	udp := findConnection(t, result.Connections, "udp", "22222")
	if udp.Protocol != "udp" || udp.LocalAddress != "0.0.0.0" || udp.LocalPort != 53 || udp.State != "UDP" || udp.Inode != "22222" {
		t.Fatalf("unexpected udp socket: %#v", udp)
	}

	if result.DNSCache[0].IPAddress != "1.1.1.1" || result.DNSCache[1].IPAddress != "2001:4860:4860::8888" {
		t.Fatalf("unexpected dns cache records: %#v", result.DNSCache)
	}
	if result.Hosts[0].IPAddress != "127.0.0.1" || result.Hosts[0].Domain != "localhost" {
		t.Fatalf("unexpected hosts entry: %#v", result.Hosts)
	}
	defaultRoute := findRoute(t, result.Routes, "0.0.0.0")
	if defaultRoute.Gateway != "10.0.0.1" || defaultRoute.Interface != "eth0" || !defaultRoute.DefaultRoute {
		t.Fatalf("unexpected default route: %#v", defaultRoute)
	}
	neighbor := result.Neighbors[0]
	if neighbor.IPAddress != "10.0.0.1" || neighbor.MACAddress != "00:11:22:33:44:55" || neighbor.Interface != "eth0" {
		t.Fatalf("unexpected arp neighbor: %#v", neighbor)
	}
	dropRule := findFirewallRule(t, result.FirewallRules, "INPUT", "DROP")
	if dropRule.Source != filepath.Join("etc", "iptables", "rules.v4") || dropRule.Table != "filter" || dropRule.Protocol != "tcp" || dropRule.DestinationPort != "22" {
		t.Fatalf("unexpected iptables firewall rule: %#v", dropRule)
	}
	if !containsString(dropRule.RiskTags, "ssh_exposure") || !containsString(dropRule.RiskTags, "drop_rule") {
		t.Fatalf("expected firewall risk tags, got %#v", dropRule.RiskTags)
	}
	policyRule := result.PolicyRules[0]
	if policyRule.Source != filepath.Join("etc", "iproute2", "rules.v4") || policyRule.Priority != "100" || policyRule.From != "10.0.0.0/24" || policyRule.Table != "100" {
		t.Fatalf("unexpected policy rule: %#v", policyRule)
	}
}

func TestCollectParsesRuntimeNetworkSnapshots(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "run", "host-collector", "runtime", "iptables-save.v4"), "*filter\n-A INPUT -p tcp --dport 2222 -j ACCEPT\nCOMMIT\n")
	mustWrite(t, filepath.Join(root, "run", "host-collector", "runtime", "nft-list-ruleset.txt"), "table inet filter { chain input { tcp dport 22 drop } }\n")
	mustWrite(t, filepath.Join(root, "run", "host-collector", "runtime", "ip-route.txt"), "default via 10.0.0.1 dev eth0 proto dhcp metric 100\n10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.2\n")
	mustWrite(t, filepath.Join(root, "run", "host-collector", "runtime", "ip-rule.txt"), "100: from 10.0.0.0/24 lookup 100\n")
	mustWrite(t, filepath.Join(root, "run", "systemd", "resolve", "cache.txt"), "example.test A 10.0.0.9 ttl=120\n")
	mustWrite(t, filepath.Join(root, "var", "lib", "misc", "dnsmasq.leases"), "1710000000 aa:bb:cc:dd:ee:ff 10.0.0.20 host1 01:aa\n")

	result, err := Collect(root)
	if err != nil {
		t.Fatalf("collect runtime network: %v", err)
	}

	for _, source := range []string{
		filepath.Join("run", "host-collector", "runtime", "iptables-save.v4"),
		filepath.Join("run", "host-collector", "runtime", "nft-list-ruleset.txt"),
		filepath.Join("run", "host-collector", "runtime", "ip-route.txt"),
		filepath.Join("run", "host-collector", "runtime", "ip-rule.txt"),
		filepath.Join("run", "systemd", "resolve", "cache.txt"),
		filepath.Join("var", "lib", "misc", "dnsmasq.leases"),
	} {
		if !containsString(result.Sources, source) {
			t.Fatalf("expected runtime source %s in %#v", source, result.Sources)
		}
	}
	runtimeRule := findFirewallRule(t, result.FirewallRules, "INPUT", "ACCEPT")
	if runtimeRule.SourceType != "runtime" || runtimeRule.DestinationPort != "2222" {
		t.Fatalf("unexpected runtime iptables rule: %#v", runtimeRule)
	}
	nftRule := findFirewallRule(t, result.FirewallRules, "input", "drop")
	if nftRule.SourceType != "runtime" || nftRule.Table != "filter" || nftRule.Protocol != "tcp" || nftRule.DestinationPort != "22" {
		t.Fatalf("unexpected nft runtime rule: %#v", nftRule)
	}
	runtimeRoute := findRoute(t, result.Routes, "0.0.0.0/0")
	if runtimeRoute.SourceType != "runtime" || runtimeRoute.Gateway != "10.0.0.1" {
		t.Fatalf("unexpected runtime route: %#v", runtimeRoute)
	}
	if result.PolicyRules[0].SourceType != "runtime" {
		t.Fatalf("expected runtime policy rule, got %#v", result.PolicyRules)
	}
	if len(result.DNSCache) != 2 {
		t.Fatalf("expected runtime dns cache records, got %#v", result.DNSCache)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func findConnection(t *testing.T, connections []Connection, protocol string, inode string) Connection {
	t.Helper()
	for _, connection := range connections {
		if connection.Protocol == protocol && connection.Inode == inode {
			return connection
		}
	}
	t.Fatalf("expected %s connection with inode %s in %#v", protocol, inode, connections)
	return Connection{}
}

func findRoute(t *testing.T, routes []Route, destination string) Route {
	t.Helper()
	for _, route := range routes {
		if route.Destination == destination {
			return route
		}
	}
	t.Fatalf("expected route destination %s in %#v", destination, routes)
	return Route{}
}

func findFirewallRule(t *testing.T, rules []FirewallRule, chain string, action string) FirewallRule {
	t.Helper()
	for _, rule := range rules {
		if rule.Chain == chain && rule.Action == action {
			return rule
		}
	}
	t.Fatalf("expected firewall rule %s/%s in %#v", chain, action, rules)
	return FirewallRule{}
}

func mustWrite(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir fixture: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}

func TestCollectToleratesMissingProcNetFiles(t *testing.T) {
	result, err := Collect(t.TempDir())
	if err != nil {
		t.Fatalf("collect missing network files: %v", err)
	}
	if len(result.Connections) != 0 {
		t.Fatalf("expected no connections, got %#v", result.Connections)
	}
	if len(result.Sources) != 0 {
		t.Fatalf("expected no sources, got %#v", result.Sources)
	}
}
