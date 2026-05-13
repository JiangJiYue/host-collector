package collector

import "windows-host-collector/models"

type enumeratedProcessWindow struct {
	PID    int32
	Window models.ProcessWindow
}

func groupProcessWindowsByPID(rows []enumeratedProcessWindow) map[int32][]models.ProcessWindow {
	grouped := make(map[int32][]models.ProcessWindow, len(rows))
	for _, row := range rows {
		grouped[row.PID] = append(grouped[row.PID], row.Window)
	}
	return grouped
}
