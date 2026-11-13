package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// clockTicks is USER_HZ, the unit of utime/stime in /proc/<pid>/stat; Linux
// exports it as 100 on every mainstream architecture.
const clockTicks = 100

type procStats struct {
	threads int
	rssKB   int
	peakKB  int
	cpuMs   float64
}

// readProc samples one process; pid may be "self".
func readProc(pid string) (procStats, error) {
	var stats procStats
	status, err := os.ReadFile("/proc/" + pid + "/status")
	if err != nil {
		return stats, err
	}
	for _, field := range []struct {
		name   string
		target *int
	}{{"Threads", &stats.threads}, {"VmRSS", &stats.rssKB}, {"VmHWM", &stats.peakKB}} {
		value, err := statusValue(string(status), field.name)
		if err != nil {
			return stats, fmt.Errorf("/proc/%s/status: %w", pid, err)
		}
		*field.target = value
	}
	stat, err := os.ReadFile("/proc/" + pid + "/stat")
	if err != nil {
		return stats, err
	}
	// The command name may contain spaces, so fields are counted after ")".
	_, rest, found := strings.Cut(string(stat), ") ")
	fields := strings.Fields(rest)
	if !found || len(fields) < 13 {
		return stats, fmt.Errorf("/proc/%s/stat has an unexpected format", pid)
	}
	utime, errUser := strconv.ParseFloat(fields[11], 64)
	stime, errSystem := strconv.ParseFloat(fields[12], 64)
	if errUser != nil || errSystem != nil {
		return stats, fmt.Errorf("/proc/%s/stat has invalid CPU times", pid)
	}
	stats.cpuMs = (utime + stime) * 1000 / clockTicks
	return stats, nil
}

func statusValue(text, key string) (int, error) {
	for _, line := range strings.Split(text, "\n") {
		if value, found := strings.CutPrefix(line, key+":"); found {
			fields := strings.Fields(value)
			if len(fields) == 0 {
				return 0, fmt.Errorf("empty %s", key)
			}
			return strconv.Atoi(fields[0])
		}
	}
	return 0, fmt.Errorf("%s is missing", key)
}
