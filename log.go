package main

import (
	"os"
	"path/filepath"
	"strconv"
	"time"
)

const defaultLogDir = ".agent-command-guard"

func dailyLogFileName(now time.Time) string {
	return now.Format("2006-01-02") + "-acg.jsonl"
}

func loggingEnabled() bool {
	return os.Getenv("ACG_LOG") != "0"
}

func logFilePath(now time.Time) string {
	if path := os.Getenv("ACG_LOG_PATH"); path != "" {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, defaultLogDir, dailyLogFileName(now))
}

func resolveIntegration(cursor bool) string {
	if cursor {
		return "cursor"
	}
	if integration := os.Getenv("ACG_INTEGRATION"); integration != "" {
		return integration
	}
	return "codex"
}

func trimJSONOuterWhitespace(data []byte) []byte {
	start := skipJSONSpace(data, 0)
	if start >= len(data) {
		return nil
	}
	end := len(data)
	for end > start && isASCIISpace(data[end-1]) {
		end--
	}
	return data[start:end]
}

func logHookDecision(body []byte, integration string, allowed bool) {
	if !loggingEnabled() {
		return
	}
	payload := trimJSONOuterWhitespace(body)
	if len(payload) == 0 || payload[0] != '{' {
		return
	}
	now := time.Now()
	path := logFilePath(now)
	if path == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer func() { _ = file.Close() }()

	record := make([]byte, 0, len(payload)+128)
	record = append(record, `{"t":`...)
	record = strconv.AppendInt(record, now.UnixMilli(), 10)
	record = append(record, `,"s":"`...)
	if allowed {
		record = append(record, '+')
	} else {
		record = append(record, '-')
	}
	record = append(record, `"`...)
	record = append(record, `,"c":`...)
	record = appendJSONString(record, integration)
	record = append(record, `,"d":`...)
	record = append(record, payload...)
	record = append(record, '}', '\n')
	_, _ = file.Write(record)
}
