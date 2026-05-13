package history

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Result struct {
	Records []OperationRecord `json:"records"`
	Sources []string          `json:"sources"`
}

type OperationRecord struct {
	Event         string `json:"event"`
	OperationTime string `json:"operationTime,omitempty"`
	File          string `json:"file"`
	FilePath      string `json:"filePath"`
	Source        string `json:"source"`
	Platform      string `json:"platform"`
}

type passwdUser struct {
	Username string
	Home     string
}

var bearerTokenPattern = regexp.MustCompile(`(?i)(Authorization:\s*Bearer\s+)[^"'\s]+`)

func Collect(root string) (Result, error) {
	users, err := readPasswdUsers(filepath.Join(root, "etc", "passwd"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Result{}, nil
		}
		return Result{}, err
	}
	var result Result
	for _, user := range users {
		if user.Home == "" || user.Home == "/nonexistent" {
			continue
		}
		if err := collectBashHistory(root, user, &result); err != nil {
			return Result{}, err
		}
		if err := collectZshHistory(root, user, &result); err != nil {
			return Result{}, err
		}
	}
	sort.Strings(result.Sources)
	return result, nil
}

func readPasswdUsers(path string) ([]passwdUser, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var users []passwdUser
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) < 6 {
			continue
		}
		users = append(users, passwdUser{Username: fields[0], Home: fields[5]})
	}
	return users, scanner.Err()
}

func collectBashHistory(root string, user passwdUser, result *Result) error {
	relativePath := strings.TrimPrefix(filepath.Join(user.Home, ".bash_history"), string(filepath.Separator))
	path := filepath.Join(root, relativePath)
	records, err := readBashHistory(path, relativePath, user.Username)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if len(records) > 0 {
		result.Records = append(result.Records, records...)
		result.Sources = append(result.Sources, relativePath)
	}
	return nil
}

func collectZshHistory(root string, user passwdUser, result *Result) error {
	relativePath := strings.TrimPrefix(filepath.Join(user.Home, ".zsh_history"), string(filepath.Separator))
	path := filepath.Join(root, relativePath)
	records, err := readZshHistory(path, relativePath, user.Username)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if len(records) > 0 {
		result.Records = append(result.Records, records...)
		result.Sources = append(result.Sources, relativePath)
	}
	return nil
}

func readBashHistory(path string, relativePath string, username string) ([]OperationRecord, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var records []OperationRecord
	var pendingTimestamp string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			if ts := parseBashTimestamp(strings.TrimPrefix(line, "#")); ts != "" {
				pendingTimestamp = ts
			}
			continue
		}
		records = append(records, OperationRecord{
			Event:         "shell_history",
			OperationTime: pendingTimestamp,
			File:          redactCommand(line),
			FilePath:      relativePath,
			Source:        username + ":bash_history",
			Platform:      "linux",
		})
		pendingTimestamp = ""
	}
	return records, scanner.Err()
}

func readZshHistory(path string, relativePath string, username string) ([]OperationRecord, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var records []OperationRecord
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		timestamp, command := parseZshHistoryLine(line)
		records = append(records, OperationRecord{
			Event:         "shell_history",
			OperationTime: timestamp,
			File:          redactCommand(command),
			FilePath:      relativePath,
			Source:        username + ":zsh_history",
			Platform:      "linux",
		})
	}
	return records, scanner.Err()
}

func parseBashTimestamp(value string) string {
	seconds, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil || seconds <= 0 {
		return ""
	}
	return time.Unix(seconds, 0).UTC().Format(time.RFC3339)
}

func parseZshHistoryLine(line string) (string, string) {
	if !strings.HasPrefix(line, ": ") {
		return "", line
	}
	rawTimestamp, rest, ok := strings.Cut(strings.TrimPrefix(line, ": "), ":")
	if !ok {
		return "", line
	}
	_, command, ok := strings.Cut(rest, ";")
	if !ok {
		return parseBashTimestamp(rawTimestamp), line
	}
	return parseBashTimestamp(rawTimestamp), command
}

func redactCommand(command string) string {
	return bearerTokenPattern.ReplaceAllString(command, "${1}[REDACTED]")
}
