package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"collector-shared/appcore"
	"collector-shared/localbundle"
	"collector-shared/localcli"
	"collector-shared/localoutputdir"
	"collector-shared/runmode"
	"collector-shared/runtimecheck"
	"linux-host-collector/internal/runner"
)

var buildVersion = "phase2-local"
var effectiveUID = os.Geteuid

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return runScan([]string{})
	}
	if args[0] == "--version" || args[0] == "-version" {
		fmt.Println(buildVersion)
		return nil
	}
	switch args[0] {
	case "scan":
		return runScan(args[1:])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runScan(args []string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	flags := flag.NewFlagSet("scan", flag.ContinueOnError)
	root := flags.String("root", "/", "root filesystem path")
	outputDir := flags.String("output-dir", "", "output directory for manifest.json and sections/*.json")
	include := flags.String("include", "", "comma-separated collection scope to include")
	exclude := flags.String("exclude", "", "comma-separated collection scope to exclude")
	days := flags.Int("days", 7, "scan time window in days: 7, 14, or 30")
	agentID := flags.String("agent-id", "", "agent id")
	scanID := flags.String("scan-id", "", "scan id")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *scanID == "" {
		*scanID = appcore.FormatScanID(time.Now())
	}
	*outputDir = localoutputdir.Resolve(*outputDir, *scanID)
	if *agentID == "" {
		*agentID = defaultAgentID()
	}
	return runOSSLocalScan(ossLocalOptions{
		Root:         *root,
		OutputDir:    *outputDir,
		AgentID:      *agentID,
		ScanID:       *scanID,
		IncludeValue: *include,
		ExcludeValue: *exclude,
		Days:         *days,
	})
}

type ossLocalOptions struct {
	Root         string
	OutputDir    string
	AgentID      string
	ScanID       string
	IncludeValue string
	ExcludeValue string
	Days         int
}

func runOSSLocalScan(options ossLocalOptions) error {
	if options.OutputDir == "" {
		return fmt.Errorf("local scan requires --output-dir")
	}
	cliOptions, err := localcli.Resolve(localcli.Options{
		Include: options.IncludeValue,
		Exclude: options.ExcludeValue,
		Days:    options.Days,
	})
	if err != nil {
		return err
	}
	result, err := runner.RunLocalScan(runner.Config{
		Root:       options.Root,
		AgentID:    options.AgentID,
		ScanID:     options.ScanID,
		ScanScope:  cliOptions.Scope,
		WindowDays: cliOptions.Days,
		StatusSink: appcore.NewConsoleStatusSink(os.Stdout),
	})
	if err != nil {
		return err
	}
	metadata := runmode.OutputMetadata{
		Edition:         runmode.EditionOSS,
		RunMode:         runmode.ModeOSSLocal,
		AuthMode:        runmode.AuthNone,
		EncryptionState: runmode.EncryptionNone,
		CollectionScope: cliOptions.Scope,
		ToolVersion:     buildVersion,
	}
	if err := localbundle.Write(options.OutputDir, localbundle.Bundle{
		Metadata: metadata,
		LocalCLI: cliOptions,
		Sections: result.Envelope.Sections,
	}); err != nil {
		return err
	}
	emitMessage(fmt.Sprintf("本地扫描 sections 已写入: %s", options.OutputDir))
	return nil
}

func defaultAgentID() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "linux-agent"
	}
	return "linux-" + hostname
}

func requireRoot() error {
	return runtimecheck.RequireRoot(effectiveUID()).Err()
}

func emitMessage(message string) {
	appcore.NewConsoleStatusSink(os.Stdout).EmitStatus(appcore.StatusEvent{
		Type:    appcore.EventScanCompleted,
		State:   appcore.StateCompleted,
		Message: message,
	})
}
