package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type procStats struct {
	threads int
	rssKB   int
	peakKB  int
	// pssKB charges shared pages proportionally, so a sum over processes
	// does not count shared libraries once per process the way RSS does.
	pssKB int
	cpuMs float64
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
	rollup, err := os.ReadFile("/proc/" + pid + "/smaps_rollup")
	if err != nil {
		return stats, err
	}
	if stats.pssKB, err = statusValue(string(rollup), "Pss"); err != nil {
		return stats, fmt.Errorf("/proc/%s/smaps_rollup: %w", pid, err)
	}
	// schedstat has nanosecond run times; /proc/<pid>/stat rounds each
	// process down to 10 ms ticks, which zeroes short-lived handshakes.
	tasks, err := filepath.Glob("/proc/" + pid + "/task/*/schedstat")
	if err != nil || len(tasks) == 0 {
		return stats, fmt.Errorf("/proc/%s/task/*/schedstat is unavailable: %v", pid, err)
	}
	for _, task := range tasks {
		data, err := os.ReadFile(task)
		if err != nil {
			// A thread may exit between listing and reading.
			continue
		}
		fields := strings.Fields(string(data))
		if len(fields) == 0 {
			return stats, fmt.Errorf("%s is empty", task)
		}
		nanoseconds, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			return stats, fmt.Errorf("%s: %w", task, err)
		}
		stats.cpuMs += nanoseconds / 1e6
	}
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
