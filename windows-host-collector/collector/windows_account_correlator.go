package collector

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"windows-host-collector/models"
)

var nonAlphaNumeric = regexp.MustCompile(`[^a-z0-9]+`)

type accountAggregate struct {
	account        models.LocalUserAccount
	sourceSet      map[string]struct{}
	localGroupSet  map[string]struct{}
	globalGroupSet map[string]struct{}
	reasonSet      map[string]struct{}
	evidenceSet    map[string]struct{}
	nameIndexRID   *uint32
	samVDigest     string
	samFDigest     string
}

func stableUserID(sid *string, rid *uint32, username string) string {
	if sid != nil && strings.TrimSpace(*sid) != "" {
		return "user:sid:" + strings.TrimSpace(*sid)
	}
	if rid != nil {
		return fmt.Sprintf("user:rid:%d", *rid)
	}
	normalized := normalizeUsername(username)
	if normalized == "unknown" {
		return "user:unknown"
	}
	return "user:name:" + normalized
}

func correlateAccountSources(bundle accountSourceBundle) []models.LocalUserAccount {
	records := flattenAccountSourceBundle(bundle)
	aggs := make([]*accountAggregate, 0, len(records))
	bySID := map[string]*accountAggregate{}
	byRID := map[uint32]*accountAggregate{}
	byName := map[string][]*accountAggregate{}

	for _, rec := range records {
		agg := findAggregate(rec, bySID, byRID, byName)
		if agg == nil {
			if rec.Source == accountSourceSession {
				continue
			}
			agg = newAccountAggregate(rec)
			aggs = append(aggs, agg)
		}
		mergeRecordIntoAggregate(agg, rec)

		if rec.SID != nil && strings.TrimSpace(*rec.SID) != "" {
			bySID[strings.TrimSpace(*rec.SID)] = agg
		}
		if rec.RID != nil {
			byRID[*rec.RID] = agg
		}
		if normalized := normalizeUsername(rec.Username); normalized != "unknown" {
			byName[normalized] = appendUniqueAggregate(byName[normalized], agg)
		}
	}

	result := make([]models.LocalUserAccount, 0, len(aggs))
	for _, agg := range aggs {
		agg.account.ID = stableUserID(agg.account.SID, agg.account.RID, agg.account.Username)
		agg.account.LocalGroups = sortedSetValues(agg.localGroupSet)
		agg.account.GlobalGroups = sortedSetValues(agg.globalGroupSet)
		agg.account.Sources = orderedSources(agg.sourceSet)
		applyShadowDetection(agg, bundle)
	}
	applyCrossAccountSAMDetection(aggs)
	for _, agg := range aggs {
		result = append(result, agg.account)
	}
	sortAccounts(result)

	return result
}

func correlateAccounts(bundle accountSourceBundle) []models.LocalUserAccount {
	return correlateAccountSources(bundle)
}

func newAccountAggregate(rec accountSourceRecord) *accountAggregate {
	account := models.LocalUserAccount{
		ID:             stableUserID(rec.SID, rec.RID, rec.Username),
		Username:       rec.Username,
		FullName:       copyStringPtr(rec.FullName),
		SID:            copyStringPtr(rec.SID),
		RID:            copyUint32Ptr(rec.RID),
		AccountType:    rec.AccountType,
		Privilege:      rec.Privilege,
		Comment:        copyStringPtr(rec.Comment),
		LogonScript:    copyStringPtr(rec.LogonScript),
		LastLogon:      copyStringPtr(rec.LastLogon),
		ExpiresAt:      copyStringPtr(rec.ExpiresAt),
		LoginFailures:  rec.LoginFailures,
		LoginSuccesses: rec.LoginSuccesses,
		LocalGroups:    []string{},
		GlobalGroups:   []string{},
	}
	return &accountAggregate{
		account:        account,
		sourceSet:      map[string]struct{}{},
		localGroupSet:  map[string]struct{}{},
		globalGroupSet: map[string]struct{}{},
		reasonSet:      map[string]struct{}{},
		evidenceSet:    map[string]struct{}{},
	}
}

func findAggregate(rec accountSourceRecord, bySID map[string]*accountAggregate, byRID map[uint32]*accountAggregate, byName map[string][]*accountAggregate) *accountAggregate {
	if rec.SID != nil {
		sid := strings.TrimSpace(*rec.SID)
		if sid != "" {
			if agg, ok := bySID[sid]; ok {
				if identitiesCompatible(agg.account, rec) {
					return agg
				}
			}
		}
	}
	if rec.RID != nil {
		if agg, ok := byRID[*rec.RID]; ok {
			if identitiesCompatible(agg.account, rec) {
				return agg
			}
		}
	}
	if normalized := normalizeUsername(rec.Username); normalized != "unknown" {
		for _, agg := range byName[normalized] {
			if identitiesCompatible(agg.account, rec) {
				return agg
			}
		}
	}
	return nil
}

func mergeRecordIntoAggregate(agg *accountAggregate, rec accountSourceRecord) {
	preferString(&agg.account.Username, rec.Username)
	preferStringPtr(&agg.account.FullName, rec.FullName)
	preferStringPtr(&agg.account.SID, rec.SID)
	preferUint32Ptr(&agg.account.RID, rec.RID)
	preferString(&agg.account.AccountType, rec.AccountType)
	preferString(&agg.account.Privilege, rec.Privilege)
	preferStringPtr(&agg.account.Comment, rec.Comment)
	preferStringPtr(&agg.account.LogonScript, rec.LogonScript)
	preferStringPtr(&agg.account.LastLogon, rec.LastLogon)
	preferStringPtr(&agg.account.ExpiresAt, rec.ExpiresAt)
	if agg.account.LoginFailures == 0 && rec.LoginFailures != 0 {
		agg.account.LoginFailures = rec.LoginFailures
	}
	if agg.account.LoginSuccesses == 0 && rec.LoginSuccesses != 0 {
		agg.account.LoginSuccesses = rec.LoginSuccesses
	}
	agg.account.Disabled = agg.account.Disabled || rec.Disabled

	for _, group := range rec.LocalGroups {
		group = strings.TrimSpace(group)
		if group != "" {
			agg.localGroupSet[group] = struct{}{}
		}
	}
	for _, group := range rec.GlobalGroups {
		group = strings.TrimSpace(group)
		if group != "" {
			agg.globalGroupSet[group] = struct{}{}
		}
	}

	if rec.Source != "" {
		agg.sourceSet[rec.Source] = struct{}{}
	}
	agg.account.Visibility.NetAPI = agg.account.Visibility.NetAPI || rec.Source == accountSourceNetAPI || rec.NetAPIVisible
	agg.account.Visibility.WMI = agg.account.Visibility.WMI || rec.Source == accountSourceWMI || rec.WMIVisible
	agg.account.Visibility.NetCommand = agg.account.Visibility.NetCommand || rec.Source == accountSourceNetCmd || rec.NetCommandVisible
	agg.account.Visibility.SAMAliasMembership = agg.account.Visibility.SAMAliasMembership || rec.SAMAliasMembership
	agg.account.Visibility.SAMRidKey = agg.account.Visibility.SAMRidKey || rec.SAMRidKey || rec.RIDKeyPresent
	agg.account.Visibility.SAMNameIndex = agg.account.Visibility.SAMNameIndex || rec.SAMNameIndex || rec.NameIndexPresent

	if rec.NameIndexRID != nil && agg.nameIndexRID == nil {
		agg.nameIndexRID = copyUint32Ptr(rec.NameIndexRID)
	}
	if rec.SAM != nil {
		if agg.account.SAM == nil {
			agg.account.SAM = &models.SAMAccountEvidence{}
		}
		mergeSAMEvidence(agg.account.SAM, rec.SAM)
		if strings.TrimSpace(rec.SAM.VDigest) != "" && agg.samVDigest == "" {
			agg.samVDigest = strings.TrimSpace(rec.SAM.VDigest)
		}
		if strings.TrimSpace(rec.SAM.FDigest) != "" && agg.samFDigest == "" {
			agg.samFDigest = strings.TrimSpace(rec.SAM.FDigest)
		}
	}
}

func applyShadowDetection(agg *accountAggregate, bundle accountSourceBundle) {
	hasSAM := hasSource(agg.sourceSet, accountSourceSAM)
	hasNetAPI := hasSource(agg.sourceSet, accountSourceNetAPI)
	hasWMI := hasSource(agg.sourceSet, accountSourceWMI)
	hasNetCommand := hasSource(agg.sourceSet, accountSourceNetCmd)
	hasStrongEvidence := agg.account.Visibility.SAMRidKey && agg.account.Visibility.SAMNameIndex
	netAPIFailed := bundle.NetAPIErr != nil
	wmiFailed := bundle.WMIErr != nil
	netCommandFailed := bundle.NetCmdErr != nil
	netCommandSnapshotAvailable := bundle.NetCmd != nil
	apiChecksComplete := !netAPIFailed && !wmiFailed
	netCommandCheckComplete := !netCommandFailed && netCommandSnapshotAvailable
	confirmed := false
	suspicious := false
	if bundle.SAMErr != nil {
		_, _, reasons, evidence := samUncheckedShadow(bundle.SAMErr)
		for _, reason := range reasons {
			addReason(agg.reasonSet, reason)
		}
		for _, item := range evidence {
			addEvidence(agg.evidenceSet, item)
		}
	}

	if apiChecksComplete && hasSAM && !hasNetAPI && !hasWMI {
		addReason(agg.reasonSet, shadowReasonSAMOnly)
		confirmed = true
	}
	if agg.account.Visibility.SAMRidKey && !agg.account.Visibility.SAMNameIndex {
		addReason(agg.reasonSet, shadowReasonSAMNameIndexMissing)
		confirmed = true
	}
	if agg.account.Visibility.SAMNameIndex && !agg.account.Visibility.SAMRidKey {
		addReason(agg.reasonSet, shadowReasonSAMRIDKeyMissing)
		confirmed = true
	}
	if agg.nameIndexRID != nil && agg.account.RID != nil && *agg.nameIndexRID != *agg.account.RID {
		addReason(agg.reasonSet, shadowReasonRIDMismatch)
		confirmed = true
	}
	if apiChecksComplete && hasSAM && !hasNetAPI {
		addReason(agg.reasonSet, shadowReasonAPIInvisible)
		if hasStrongEvidence {
			confirmed = true
		} else if !confirmed {
			suspicious = true
		}
	}
	if bundle.SAMErr == nil && apiChecksComplete && (hasNetAPI || hasWMI) && hasNetAPI != hasWMI {
		addReason(agg.reasonSet, shadowReasonSourceMismatch)
		if !confirmed {
			suspicious = true
		}
	}
	if netCommandCheckComplete && hasSAM && !hasNetCommand && !isBuiltinLocalAccount(agg.account) {
		addReason(agg.reasonSet, shadowReasonNetCommandInvisible)
		if hasStrongEvidence {
			confirmed = true
		} else if !confirmed {
			suspicious = true
		}
	}
	if bundle.SAMErr != nil && hasDollarSuffixLocalAccount(agg.account) {
		addReason(agg.reasonSet, shadowReasonDollarSuffixLocalAccount)
		suspicious = true
	}
	if bundle.SAMErr != nil && isAdminGroupMember(agg.account) && !isBuiltinLocalAccount(agg.account) {
		addReason(agg.reasonSet, shadowReasonAdminGroupMember)
		suspicious = true
	}
	if netCommandCheckComplete && bundle.SAMErr != nil && (hasNetAPI || hasWMI) && !hasNetCommand && !isBuiltinLocalAccount(agg.account) {
		addReason(agg.reasonSet, shadowReasonNetCommandInvisible)
		suspicious = true
	}

	reasons := sortedSetValues(agg.reasonSet)
	evidence := sortedSetValues(agg.evidenceSet)
	switch {
	case confirmed:
		agg.account.Shadow = models.ShadowAccountDetection{
			IsShadowAccount: true,
			Status:          shadowStatusConfirmed,
			Confidence:      shadowConfidenceHigh,
			Reasons:         reasons,
			Evidence:        evidence,
		}
	case suspicious:
		agg.account.Shadow = models.ShadowAccountDetection{
			IsShadowAccount: true,
			Status:          shadowStatusSuspicious,
			Confidence:      shadowConfidenceMedium,
			Reasons:         reasons,
			Evidence:        evidence,
		}
	default:
		status := shadowStatusClean
		if bundle.SAMErr != nil {
			status = shadowStatusUnchecked
		}
		agg.account.Shadow = models.ShadowAccountDetection{
			IsShadowAccount: false,
			Status:          status,
			Confidence:      shadowConfidenceNone,
			Reasons:         reasons,
			Evidence:        evidence,
		}
	}
}

func applyCrossAccountSAMDetection(aggs []*accountAggregate) {
	vDigestCounts := map[string]int{}
	fDigestCounts := map[string]int{}
	for _, agg := range aggs {
		if strings.TrimSpace(agg.samVDigest) != "" {
			vDigestCounts[strings.TrimSpace(agg.samVDigest)]++
		}
		if strings.TrimSpace(agg.samFDigest) != "" {
			fDigestCounts[strings.TrimSpace(agg.samFDigest)]++
		}
	}
	for _, agg := range aggs {
		if strings.TrimSpace(agg.samVDigest) != "" && vDigestCounts[strings.TrimSpace(agg.samVDigest)] > 1 && !isBuiltinLocalAccount(agg.account) {
			addReason(agg.reasonSet, shadowReasonSAMVShared)
			agg.account.Shadow.IsShadowAccount = true
			agg.account.Shadow.Status = shadowStatusConfirmed
			agg.account.Shadow.Confidence = shadowConfidenceHigh
		}
		if strings.TrimSpace(agg.samFDigest) != "" && fDigestCounts[strings.TrimSpace(agg.samFDigest)] > 1 && !isBuiltinLocalAccount(agg.account) {
			addReason(agg.reasonSet, shadowReasonSAMFShared)
			agg.account.Shadow.IsShadowAccount = true
			agg.account.Shadow.Status = shadowStatusConfirmed
			agg.account.Shadow.Confidence = shadowConfidenceHigh
		}
		if agg.account.Visibility.SAMAliasMembership && !agg.account.Visibility.NetCommand && !isBuiltinLocalAccount(agg.account) {
			addReason(agg.reasonSet, shadowReasonAdminAliasMember)
			agg.account.Shadow.IsShadowAccount = true
			agg.account.Shadow.Status = shadowStatusConfirmed
			agg.account.Shadow.Confidence = shadowConfidenceHigh
		}
		if agg.account.Shadow.IsShadowAccount {
			agg.account.Shadow.Reasons = sortedSetValues(agg.reasonSet)
		}
	}
}

func isBuiltinLocalAccount(account models.LocalUserAccount) bool {
	if account.RID == nil {
		return false
	}
	switch *account.RID {
	case 500, 501, 503, 504:
		return true
	default:
		return false
	}
}

func hasDollarSuffixLocalAccount(account models.LocalUserAccount) bool {
	username := strings.TrimSpace(account.Username)
	if !strings.HasSuffix(username, "$") {
		return false
	}
	if isBuiltinLocalAccount(account) {
		return false
	}
	if account.RID != nil && *account.RID < 1000 {
		return false
	}
	return true
}

func isAdminGroupMember(account models.LocalUserAccount) bool {
	for _, group := range account.LocalGroups {
		normalized := strings.ToLower(strings.TrimSpace(group))
		if normalized == "administrators" || strings.HasSuffix(normalized, `\administrators`) {
			return true
		}
	}
	return false
}

func mergeSAMEvidence(dst *models.SAMAccountEvidence, src *models.SAMAccountEvidence) {
	if src == nil {
		return
	}
	if dst.NameIndexRID == nil && src.NameIndexRID != nil {
		dst.NameIndexRID = copyUint32Ptr(src.NameIndexRID)
	}
	dst.RIDKeyPresent = dst.RIDKeyPresent || src.RIDKeyPresent
	dst.NameIndexPresent = dst.NameIndexPresent || src.NameIndexPresent
	if dst.FDigest == "" {
		dst.FDigest = strings.TrimSpace(src.FDigest)
	}
	if dst.VDigest == "" {
		dst.VDigest = strings.TrimSpace(src.VDigest)
	}
	preferStringPtr(&dst.ParsedUsername, src.ParsedUsername)
	preferStringPtr(&dst.ParsedFullName, src.ParsedFullName)
	preferStringPtr(&dst.ParsedComment, src.ParsedComment)
	preferUint32Ptr(&dst.Flags, src.Flags)
	preferStringPtr(&dst.LastLogon, src.LastLogon)
	if dst.LoginFailures == nil && src.LoginFailures != nil {
		dst.LoginFailures = copyIntPtr(src.LoginFailures)
	}
	if dst.LoginSuccesses == nil && src.LoginSuccesses != nil {
		dst.LoginSuccesses = copyIntPtr(src.LoginSuccesses)
	}
	if len(dst.BuiltinAliasMemberships) == 0 && len(src.BuiltinAliasMemberships) > 0 {
		dst.BuiltinAliasMemberships = append([]string{}, src.BuiltinAliasMemberships...)
	}
}

func normalizeUsername(username string) string {
	normalized := strings.TrimSpace(strings.ToLower(username))
	normalized = nonAlphaNumeric.ReplaceAllString(normalized, "-")
	normalized = strings.Trim(normalized, "-")
	if normalized == "" {
		return "unknown"
	}
	return normalized
}

func copyStringPtr(in *string) *string {
	if in == nil {
		return nil
	}
	v := strings.TrimSpace(*in)
	if v == "" {
		return nil
	}
	return &v
}

func copyUint32Ptr(in *uint32) *uint32 {
	if in == nil {
		return nil
	}
	v := *in
	return &v
}

func copyIntPtr(in *int) *int {
	if in == nil {
		return nil
	}
	v := *in
	return &v
}

func preferString(current *string, next string) {
	if strings.TrimSpace(*current) == "" && strings.TrimSpace(next) != "" {
		*current = strings.TrimSpace(next)
	}
}

func preferStringPtr(current **string, next *string) {
	if *current != nil {
		return
	}
	*current = copyStringPtr(next)
}

func preferUint32Ptr(current **uint32, next *uint32) {
	if *current != nil || next == nil {
		return
	}
	v := *next
	*current = &v
}

func sortedSetValues(set map[string]struct{}) []string {
	if len(set) == 0 {
		return []string{}
	}
	values := make([]string, 0, len(set))
	for value := range set {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

func hasSource(sources map[string]struct{}, source string) bool {
	_, ok := sources[source]
	return ok
}

func addReason(reasonSet map[string]struct{}, reason string) {
	if reason == "" {
		return
	}
	reasonSet[reason] = struct{}{}
}

func addEvidence(evidenceSet map[string]struct{}, evidence string) {
	evidence = strings.TrimSpace(evidence)
	if evidence == "" {
		return
	}
	evidenceSet[evidence] = struct{}{}
}

func orderedSources(set map[string]struct{}) []string {
	ordered := []string{}
	for _, source := range []string{accountSourceNetAPI, accountSourceWMI, accountSourceNetCmd, accountSourceSAM, accountSourceSession} {
		if _, ok := set[source]; ok {
			ordered = append(ordered, source)
		}
	}
	return ordered
}

func identitiesCompatible(existing models.LocalUserAccount, rec accountSourceRecord) bool {
	existingSID := ""
	if existing.SID != nil {
		existingSID = strings.TrimSpace(*existing.SID)
	}
	recSID := ""
	if rec.SID != nil {
		recSID = strings.TrimSpace(*rec.SID)
	}
	if existingSID != "" && recSID != "" && existingSID != recSID {
		return false
	}

	if existing.RID != nil && rec.RID != nil && *existing.RID != *rec.RID {
		return false
	}
	return true
}

func appendUniqueAggregate(list []*accountAggregate, agg *accountAggregate) []*accountAggregate {
	for _, existing := range list {
		if existing == agg {
			return list
		}
	}
	return append(list, agg)
}

func sortAccounts(accounts []models.LocalUserAccount) {
	sort.Slice(accounts, func(i, j int) bool {
		left := accounts[i]
		right := accounts[j]

		leftUser := normalizeUsername(left.Username)
		rightUser := normalizeUsername(right.Username)
		if leftUser != rightUser {
			return leftUser < rightUser
		}

		leftRID, leftHasRID := ridSortValue(left.RID)
		rightRID, rightHasRID := ridSortValue(right.RID)
		if leftHasRID != rightHasRID {
			return leftHasRID
		}
		if leftRID != rightRID {
			return leftRID < rightRID
		}

		leftSID := sidSortValue(left.SID)
		rightSID := sidSortValue(right.SID)
		if leftSID != rightSID {
			return leftSID < rightSID
		}
		return left.ID < right.ID
	})
}

func ridSortValue(rid *uint32) (uint32, bool) {
	if rid == nil {
		return 0, false
	}
	return *rid, true
}

func sidSortValue(sid *string) string {
	if sid == nil {
		return ""
	}
	return strings.TrimSpace(*sid)
}

func formatAccountDiagnostics(accounts []models.LocalUserAccount) string {
	if len(accounts) == 0 {
		return "accounts=[]"
	}

	lines := make([]string, 0, len(accounts))
	for _, account := range accounts {
		sid := ""
		if account.SID != nil {
			sid = strings.TrimSpace(*account.SID)
		}
		rid := ""
		if account.RID != nil {
			rid = fmt.Sprintf("%d", *account.RID)
		}
		lines = append(lines, fmt.Sprintf(
			"username=%s sid=%s rid=%s sources=%s visibility=netApi:%t,wmi:%t,netCommand:%t,samRidKey:%t,samNameIndex:%t shadow=%s/%s/%t",
			account.Username,
			sid,
			rid,
			strings.Join(account.Sources, ","),
			account.Visibility.NetAPI,
			account.Visibility.WMI,
			account.Visibility.NetCommand,
			account.Visibility.SAMRidKey,
			account.Visibility.SAMNameIndex,
			account.Shadow.Status,
			account.Shadow.Confidence,
			account.Shadow.IsShadowAccount,
		))
	}
	return strings.Join(lines, "\n")
}

func formatProviderDiagnostics(bundle accountSourceBundle) string {
	netapi := summarizeProviderRecords(bundle.NetAPI)
	wmi := summarizeProviderRecords(bundle.WMI)
	netcmd := summarizeProviderRecords(bundle.NetCmd)
	sam := summarizeProviderRecords(bundle.SAM)

	netapiSet := make(map[string]struct{}, len(netapi))
	wmiSet := make(map[string]struct{}, len(wmi))
	netcmdSet := make(map[string]struct{}, len(netcmd))
	samSet := make(map[string]struct{}, len(sam))
	for _, value := range netapi {
		netapiSet[value] = struct{}{}
	}
	for _, value := range wmi {
		wmiSet[value] = struct{}{}
	}
	for _, value := range netcmd {
		netcmdSet[value] = struct{}{}
	}
	for _, value := range sam {
		samSet[value] = struct{}{}
	}

	return fmt.Sprintf(
		"netapi=%s wmi=%s netcmd=%s sam=%s netapi_only=%s wmi_only=%s netcmd_only=%s sam_only=%s",
		formatDiagnosticList(netapi),
		formatDiagnosticList(wmi),
		formatDiagnosticList(netcmd),
		formatDiagnosticList(sam),
		formatDiagnosticList(setDifference(netapiSet, wmiSet, netcmdSet, samSet)),
		formatDiagnosticList(setDifference(wmiSet, netapiSet, netcmdSet, samSet)),
		formatDiagnosticList(setDifference(netcmdSet, netapiSet, wmiSet, samSet)),
		formatDiagnosticList(setDifference(samSet, netapiSet, wmiSet, netcmdSet)),
	)
}

func summarizeProviderRecords(records []accountSourceRecord) []string {
	values := make([]string, 0, len(records))
	for _, record := range records {
		username := strings.TrimSpace(record.Username)
		if username == "" {
			username = "unknown"
		}
		if record.RID != nil {
			values = append(values, fmt.Sprintf("%s#%d", username, *record.RID))
			continue
		}
		values = append(values, username)
	}
	sort.Strings(values)
	return values
}

func setDifference(base map[string]struct{}, excludes ...map[string]struct{}) []string {
	values := make([]string, 0, len(base))
	for value := range base {
		blocked := false
		for _, exclude := range excludes {
			if _, ok := exclude[value]; ok {
				blocked = true
				break
			}
		}
		if blocked {
			continue
		}
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

func formatDiagnosticList(values []string) string {
	return "[" + strings.Join(values, ",") + "]"
}
