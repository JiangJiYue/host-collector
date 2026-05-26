package collector

import (
	"errors"
	"windows-host-collector/models"
)

const (
	accountSourceNetAPI  = "netApi"
	accountSourceWMI     = "wmi"
	accountSourceNetCmd  = "netCommand"
	accountSourceSAM     = "sam"
	accountSourceSession = "session"
)

const (
	shadowStatusConfirmed  = "confirmed"
	shadowStatusSuspicious = "suspicious"
	shadowStatusClean      = "clean"
	shadowStatusUnchecked  = "unchecked"
)

const (
	shadowConfidenceHigh   = "high"
	shadowConfidenceMedium = "medium"
	shadowConfidenceLow    = "low"
	shadowConfidenceNone   = "none"
)

const (
	shadowReasonSAMOnly                  = "SAM_ONLY"
	shadowReasonSAMNameIndexMissing      = "SAM_NAME_INDEX_MISSING"
	shadowReasonSAMRIDKeyMissing         = "SAM_RID_KEY_MISSING"
	shadowReasonRIDMismatch              = "RID_MISMATCH"
	shadowReasonAPIInvisible             = "API_INVISIBLE"
	shadowReasonNetCommandInvisible      = "NET_COMMAND_INVISIBLE"
	shadowReasonSAMFShared               = "SAM_F_SHARED"
	shadowReasonSAMVShared               = "SAM_V_SHARED"
	shadowReasonBuiltinRIDAbuse          = "BUILTIN_RID_ABUSE"
	shadowReasonAdminAliasMember         = "ADMIN_ALIAS_MEMBER"
	shadowReasonRIDSequenceAbnormal      = "RID_SEQUENCE_ABNORMAL"
	shadowReasonNetAPICommandMismatch    = "NETAPI_COMMAND_MISMATCH"
	shadowReasonWMICommandMismatch       = "WMI_COMMAND_MISMATCH"
	shadowReasonSourceMismatch           = "SOURCE_MISMATCH"
	shadowReasonSAMUnchecked             = "SAM_UNCHECKED"
	shadowReasonDollarSuffixLocalAccount = "DOLLAR_SUFFIX_LOCAL_ACCOUNT"
	shadowReasonAdminGroupMember         = "ADMIN_GROUP_MEMBER"
)

type accountSourceBundle struct {
	NetAPI    []accountSourceRecord
	WMI       []accountSourceRecord
	NetCmd    []accountSourceRecord
	SAM       []accountSourceRecord
	Session   []accountSourceRecord
	NetAPIErr error
	WMIErr    error
	NetCmdErr error
	SAMErr    error
}

type accountSourceRecord struct {
	Username           string
	FullName           *string
	SID                *string
	RID                *uint32
	AccountType        string
	Privilege          string
	Comment            *string
	LogonScript        *string
	LastLogon          *string
	ExpiresAt          *string
	LoginFailures      int
	LoginSuccesses     int
	LocalGroups        []string
	GlobalGroups       []string
	Disabled           bool
	Source             string
	NetAPIVisible      bool
	WMIVisible         bool
	NetCommandVisible  bool
	SAMAliasMembership bool
	SAMRidKey          bool
	SAMNameIndex       bool
	NameIndexRID       *uint32
	RIDKeyPresent      bool
	NameIndexPresent   bool
	SAM                *models.SAMAccountEvidence
}

func normalizeSourceRecord(record accountSourceRecord, source string) accountSourceRecord {
	if record.Source == "" {
		record.Source = source
	}
	return record
}

func flattenAccountSourceBundle(bundle accountSourceBundle) []accountSourceRecord {
	records := make([]accountSourceRecord, 0, len(bundle.NetAPI)+len(bundle.WMI)+len(bundle.NetCmd)+len(bundle.SAM)+len(bundle.Session))
	for _, rec := range bundle.NetAPI {
		records = append(records, normalizeSourceRecord(rec, accountSourceNetAPI))
	}
	for _, rec := range bundle.WMI {
		records = append(records, normalizeSourceRecord(rec, accountSourceWMI))
	}
	for _, rec := range bundle.NetCmd {
		records = append(records, normalizeSourceRecord(rec, accountSourceNetCmd))
	}
	for _, rec := range bundle.SAM {
		records = append(records, normalizeSourceRecord(rec, accountSourceSAM))
	}
	for _, rec := range bundle.Session {
		records = append(records, normalizeSourceRecord(rec, accountSourceSession))
	}
	return records
}

func samUncheckedShadow(err error) (string, string, []string, []string) {
	reasons := []string{shadowReasonSAMUnchecked}
	evidence := []string{}
	if err != nil && !errors.Is(err, nil) {
		evidence = append(evidence, err.Error())
	}
	return shadowStatusUnchecked, shadowConfidenceNone, reasons, evidence
}
