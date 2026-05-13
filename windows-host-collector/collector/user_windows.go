//go:build windows

package collector

import (
	"context"
	"log"
	"windows-host-collector/models"
	"windows-host-collector/utils"
)

func (uc *UserCollector) collectPlatformUsers(ctx context.Context) ([]models.LocalUserAccount, error) {
	netRecords, netErr := windowsNetAPIAccountProvider{}.collect(ctx)
	if netErr != nil && ctx.Err() != nil {
		return nil, netErr
	}
	if netErr != nil {
		log.Printf("[UserCollector] NetAPI provider failed: %v", netErr)
		netRecords = []accountSourceRecord{}
	}

	wmiRecords, wmiErr := windowsWMIAccountProvider{}.collect(ctx)
	if wmiErr != nil && ctx.Err() != nil {
		return nil, wmiErr
	}
	if wmiErr != nil {
		log.Printf("[UserCollector] WMI provider failed: %v", wmiErr)
		wmiRecords = []accountSourceRecord{}
	}

	netCmdRecords, netCmdErr := windowsNetCommandAccountProvider{}.collect(ctx)
	if netCmdErr != nil && ctx.Err() != nil {
		return nil, netCmdErr
	}
	if netCmdErr != nil {
		log.Printf("[UserCollector] net command provider failed: %v", netCmdErr)
		netCmdRecords = []accountSourceRecord{}
	}

	samRecords, samErr := windowsSAMAccountProvider{}.collect(ctx)
	if samErr != nil && ctx.Err() != nil {
		return nil, samErr
	}
	if samErr != nil {
		log.Printf("[UserCollector] SAM provider failed: %v", samErr)
		samRecords = []accountSourceRecord{}
	}

	sessionRecords, sessionErr := windowsSessionAccountProvider{}.collect(ctx)
	if sessionErr != nil && ctx.Err() != nil {
		return nil, sessionErr
	}
	if sessionErr != nil {
		log.Printf("[UserCollector] session provider failed: %v", sessionErr)
		sessionRecords = []accountSourceRecord{}
	}

	accounts := correlateAccountSources(accountSourceBundle{
		NetAPI:    netRecords,
		WMI:       wmiRecords,
		NetCmd:    netCmdRecords,
		SAM:       samRecords,
		Session:   sessionRecords,
		NetAPIErr: netErr,
		WMIErr:    wmiErr,
		NetCmdErr: netCmdErr,
		SAMErr:    samErr,
	})
	bundle := accountSourceBundle{
		NetAPI:    netRecords,
		WMI:       wmiRecords,
		NetCmd:    netCmdRecords,
		SAM:       samRecords,
		Session:   sessionRecords,
		NetAPIErr: netErr,
		WMIErr:    wmiErr,
		NetCmdErr: netCmdErr,
		SAMErr:    samErr,
	}
	utils.Info("UserCollector", "provider diagnostics: %s", formatProviderDiagnostics(bundle))
	utils.Info("UserCollector", "account diagnostics:\n%s", formatAccountDiagnostics(accounts))

	if len(accounts) == 0 && netErr != nil && wmiErr != nil {
		return nil, netErr
	}
	return accounts, nil
}
