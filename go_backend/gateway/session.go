package gateway

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	defaultSessionTTL = 30 * time.Minute
	maxSessionTTL     = 24 * time.Hour
)

var sessionIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127}$`)

// SessionSpec controls sticky egress at new client connections, not at each packet.
type SessionSpec struct {
	ID  string
	TTL time.Duration
}

// ParseSession handles the -t-<minutes> suffix separately from an arbitrary
// session ID. Incomplete and nonnumeric suffixes are invalid, never a fallback.
func ParseSession(username string) (SessionSpec, error) {
	raw, found := strings.CutPrefix(username, "session-")
	if !found {
		return SessionSpec{}, fmt.Errorf("username must match session-<ID>[-t-<minutes>]")
	}
	id := raw
	spec := SessionSpec{TTL: defaultSessionTTL}
	if separator := strings.LastIndex(raw, "-t-"); separator >= 0 {
		id = raw[:separator]
		value := raw[separator+3:]
		minutes, err := strconv.ParseInt(value, 10, 64)
		if err != nil || minutes < 1 || minutes > int64(maxSessionTTL/time.Minute) {
			return SessionSpec{}, fmt.Errorf("TTL must be between 1 and 1440 minutes")
		}
		spec.TTL = time.Duration(minutes) * time.Minute
	}
	if !sessionIDPattern.MatchString(id) {
		return SessionSpec{}, fmt.Errorf("username must match session-<ID>[-t-<minutes>]")
	}
	spec.ID = id
	return spec, nil
}

// SameSession prevents a single ID from silently changing its time limit.
func SameSession(a, b SessionSpec) bool {
	return a.ID == b.ID && a.TTL == b.TTL
}
