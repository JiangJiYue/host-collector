package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"collector-shared/appcore"
	"collector-shared/authpolicy"
	"collector-shared/localbundle"
	"collector-shared/localcli"
	"collector-shared/localoutputdir"
	"collector-shared/runmode"
	"collector-shared/upload"
	"windows-host-collector/client"
	"windows-host-collector/models"
	"windows-host-collector/scanner"
	"windows-host-collector/utils"
)

var buildVersion = "headless-local"

func main() {
	if len(os.Args) > 1 {
		if err := run(os.Args[1:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if err := runDefaultNoArgs(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runDefaultNoArgs() error {
	utils.InitLogger("", utils.INFO)
	if err := client.EnsureElevated(); err != nil {
		utils.LogError("headless", "管理员提权失败: %v", err)
		return fmt.Errorf("管理员提权失败: %v", err)
	}
	if err := runScan([]string{}); err != nil {
		utils.LogError("headless", "%s", err)
		return err
	}
	return nil
}

func run(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "scan":
			return runScan(args[1:])
		case "--version", "-version":
			fmt.Println(buildVersion)
			return nil
		}
	}
	return runScan(args)
}

func runScan(args []string) error {
	flags := flag.NewFlagSet("scan", flag.ContinueOnError)
	include := flags.String("include", "", "comma-separated collection scope to include")
	exclude := flags.String("exclude", "", "comma-separated collection scope to exclude")
	days := flags.Int("days", 7, "scan time window in days: 7, 14, or 30")
	outputDir := flags.String("output-dir", "", "output directory for manifest.json and sections/*.json")
	agentID := flags.String("agent-id", "", "agent id")
	scanID := flags.String("scan-id", "", "scan id")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *agentID == "" {
		*agentID = defaultAgentID()
	}
	if *scanID == "" {
		*scanID = appcore.FormatScanID(time.Now())
	}
	*outputDir = localoutputdir.Resolve(*outputDir, *scanID)
	return runOSSLocal(ossLocalOptions{
		OutputDir:    *outputDir,
		IncludeValue: *include,
		ExcludeValue: *exclude,
		Days:         *days,
		AgentID:      *agentID,
		ScanID:       *scanID,
		StatusSink:   appcore.NewConsoleStatusSink(os.Stdout),
	})
}

type ossLocalOptions struct {
	OutputDir    string
	IncludeValue string
	ExcludeValue string
	Days         int
	AgentID      string
	ScanID       string
	StatusSink   appcore.StatusSink
}

func runOSSLocal(options ossLocalOptions) error {
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
	result, err := runLocalScan(cliOptions.Scope, options.AgentID, options.ScanID, cliOptions.Days, options.StatusSink)
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
	sections, err := upload.NormalizePayloadMap(result)
	if err != nil {
		return err
	}
	if err := localbundle.Write(options.OutputDir, localbundle.Bundle{
		Metadata: metadata,
		LocalCLI: cliOptions,
		Sections: sections,
	}); err != nil {
		return err
	}
	emitMessage(options.StatusSink, fmt.Sprintf("本地扫描 sections 已写入: %s", options.OutputDir))
	return nil
}

func runLocalScan(scope []string, agentID string, scanID string, days int, sink appcore.StatusSink) (*models.ScanEnvelope, error) {
	hostScanner := scanner.NewHostScanner().
		WithScope(scope).
		WithProgress(func(progress scanner.ScanProgress) {
			emitScanProgress(sink, progress)
		})
	if days > 0 {
		hostScanner = hostScanner.WithPolicy(&authpolicy.Policy{LogWindowDays: days})
	}
	scan, err := hostScanner.Scan(context.Background())
	if err != nil {
		return nil, err
	}
	if scan == nil {
		return nil, fmt.Errorf("scan returned nil envelope")
	}
	if scan.PlatformProfile == nil {
		scan.PlatformProfile = &models.PlatformProfile{Platform: "windows"}
	}
	return scan, nil
}

func emitScanProgress(sink appcore.StatusSink, progress scanner.ScanProgress) {
	if sink == nil {
		return
	}
	sink.EmitStatus(appcore.StatusEvent{
		Type:      appcore.EventScanProgress,
		StageKey:  progress.StageKey,
		StageName: progress.StageName,
		State:     statusState(progress.StageState),
		Current:   progress.Current,
		Total:     progress.Total,
		Detail:    progress.Detail,
	})
}

func emitMessage(sink appcore.StatusSink, message string) {
	if sink == nil {
		return
	}
	sink.EmitStatus(appcore.StatusEvent{
		Type:    appcore.EventScanCompleted,
		State:   appcore.StateCompleted,
		Message: message,
	})
}

func statusState(value string) appcore.StatusState {
	switch value {
	case string(appcore.StateRunning):
		return appcore.StateRunning
	case string(appcore.StateCompleted):
		return appcore.StateCompleted
	case string(appcore.StateSkipped):
		return appcore.StateSkipped
	case string(appcore.StateFailed):
		return appcore.StateFailed
	case string(appcore.StateDenied):
		return appcore.StateDenied
	case string(appcore.StateDegraded):
		return appcore.StateDegraded
	default:
		return appcore.StatusState(value)
	}
}

func defaultAgentID() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "windows-agent"
	}
	return "windows-" + hostname
}
