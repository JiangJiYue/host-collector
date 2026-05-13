package collector

func decideWebLogResumePlan(source webLogSourceCandidate, current webLogFileState, previous webLogResumeState, tailBudget int64) webLogResumePlan {
	if tailBudget <= 0 {
		tailBudget = current.Size
	}

	if previous.SourceID == "" || previous.FileIdentity == "" {
		return webLogResumePlan{
			Mode:        webLogResumeModeTail,
			StartOffset: tailStartOffset(current.Size, tailBudget),
			Reason:      "missing_state",
		}
	}

	if previous.FileIdentity != current.FileIdentity {
		return webLogResumePlan{
			Mode:        webLogResumeModeTail,
			StartOffset: tailStartOffset(current.Size, tailBudget),
			Reason:      "file_identity_changed",
		}
	}

	if current.Size < previous.Size {
		return webLogResumePlan{
			Mode:        webLogResumeModeTail,
			StartOffset: tailStartOffset(current.Size, tailBudget),
			Reason:      "file_shrunk",
		}
	}

	if previous.LastOffset > 0 && current.Size >= previous.LastOffset {
		return webLogResumePlan{
			Mode:        webLogResumeModeAppend,
			StartOffset: previous.LastOffset,
			Reason:      "append_from_last_offset",
		}
	}

	return webLogResumePlan{
		Mode:        webLogResumeModeTail,
		StartOffset: tailStartOffset(current.Size, tailBudget),
		Reason:      "fallback_tail",
	}
}

func tailStartOffset(size int64, tailBudget int64) int64 {
	if tailBudget <= 0 || size <= tailBudget {
		return 0
	}
	return size - tailBudget
}
