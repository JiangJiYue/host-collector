//go:build windows

package collector

import "github.com/StackExchange/wmi"

func (nc *NetworkCollector) doWMIQuery(query string, dst interface{}) error {
	return wmi.Query(query, dst)
}
