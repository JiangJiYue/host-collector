package filesystem

import (
	"encoding/hex"
	"strings"
)

type linuxSecurityAttributes struct {
	XattrNames        []string
	HasACL            bool
	ACLTypes          []string
	SELinuxContext    string
	LinuxCapabilities string
	IntegrityXattrs   []string
	Immutable         bool
	AppendOnly        bool
}

func securityAttributesFromXattrs(xattrs map[string][]byte) linuxSecurityAttributes {
	attrs := linuxSecurityAttributes{}
	var names []string
	var aclTypes []string
	var integrity []string
	for name, value := range xattrs {
		switch {
		case name == "security.selinux":
			attrs.SELinuxContext = trimNULString(value)
			names = append(names, name)
		case name == "security.capability":
			attrs.LinuxCapabilities = hex.EncodeToString(value)
			names = append(names, name)
		case name == "system.posix_acl_access":
			attrs.HasACL = true
			aclTypes = append(aclTypes, "access")
			names = append(names, name)
		case name == "system.posix_acl_default":
			attrs.HasACL = true
			aclTypes = append(aclTypes, "default")
			names = append(names, name)
		case name == "security.ima" || name == "security.evm":
			integrity = append(integrity, name)
			names = append(names, name)
		case strings.HasPrefix(name, "trusted."):
			names = append(names, name)
		}
	}
	attrs.XattrNames = uniqueStrings(names)
	attrs.ACLTypes = uniqueStrings(aclTypes)
	attrs.IntegrityXattrs = uniqueStrings(integrity)
	return attrs
}

func trimNULString(value []byte) string {
	return strings.TrimRight(string(value), "\x00")
}
