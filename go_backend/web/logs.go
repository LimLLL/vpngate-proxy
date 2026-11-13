package web

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

var auditMu sync.Mutex

func AddLog(dir, level, module, message string) {
	auditMu.Lock()
	defer auditMu.Unlock()
	entry := map[string]any{
		"timestamp": time.Now().Format(time.RFC3339), "level": level,
		"module": module, "message": message,
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	logsDir := filepath.Join(dir, "logs")
	if os.MkdirAll(logsDir, 0o700) != nil {
		return
	}
	path := filepath.Join(logsDir, time.Now().Format("2006-01-02")+".json")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err == nil {
		_, _ = file.Write(append(data, '\n'))
		_ = file.Close()
	}
}

func cleanupOldLogs(dir string) {
	pattern := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}\.json$`)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !pattern.MatchString(entry.Name()) {
			continue
		}
		day, err := time.Parse("2006-01-02", entry.Name()[:10])
		if err != nil || time.Since(day) < 3*24*time.Hour {
			continue
		}
		_ = os.Remove(filepath.Join(dir, entry.Name()))
	}
}
