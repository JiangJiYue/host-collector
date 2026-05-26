package client

import (
	"fmt"
	"strings"
)

type shellExecuteParameters struct {
	Executable string
	Parameters string
}

func buildShellExecuteParameters(executable string, args []string) (shellExecuteParameters, error) {
	if strings.TrimSpace(executable) == "" {
		return shellExecuteParameters{}, fmt.Errorf("resolve current executable: empty path")
	}
	escaped := make([]string, 0, len(args))
	for _, arg := range args {
		escaped = append(escaped, escapeWindowsArg(arg))
	}
	return shellExecuteParameters{
		Executable: executable,
		Parameters: strings.Join(escaped, " "),
	}, nil
}

func escapeWindowsArg(arg string) string {
	if arg == "" {
		return `""`
	}
	needsQuotes := strings.ContainsAny(arg, " \t\n\v\"")
	if !needsQuotes {
		return arg
	}

	var b strings.Builder
	b.WriteByte('"')
	backslashes := 0
	for _, r := range arg {
		switch r {
		case '\\':
			backslashes++
		case '"':
			b.WriteString(strings.Repeat(`\`, backslashes*2+1))
			b.WriteRune(r)
			backslashes = 0
		default:
			if backslashes > 0 {
				b.WriteString(strings.Repeat(`\`, backslashes))
				backslashes = 0
			}
			b.WriteRune(r)
		}
	}
	if backslashes > 0 {
		b.WriteString(strings.Repeat(`\`, backslashes*2))
	}
	b.WriteByte('"')
	return b.String()
}
