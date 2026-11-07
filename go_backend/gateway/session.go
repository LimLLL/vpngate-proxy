package gateway

import (
	"fmt"
	"regexp"
	"strconv"
	"time"
)

const (
	defaultSessionTTL = 30 * time.Minute
	maxSessionTTL     = 24 * time.Hour
)

var sessionPattern = regexp.MustCompile(`^session-([a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127})(?:-t-([0-9]+))?$`)

// SessionSpec controls sticky egress at new client connections, not at each packet.
type SessionSpec struct {
	ID  string
	TTL time.Duration
}

func ParseSession(username string) (SessionSpec, error) {
	matches := sessionPattern.FindStringSubmatch(username)
	if matches == nil {
		return SessionSpec{}, fmt.Errorf("username must match session-<ID>[-t-<minutes>]")
	}
	spec := SessionSpec{ID: matches[1], TTL: defaultSessionTTL}
	if matches[2] != "" {
		minutes, err := strconv.ParseInt(matches[2], 10, 64)
		if err != nil || minutes < 1 || minutes > int64(maxSessionTTL/time.Minute) {
			return SessionSpec{}, fmt.Errorf("TTL must be between 1 and 1440 minutes")
		}
		spec.TTL = time.Duration(minutes) * time.Minute
	}
	return spec, nil
}

// SameSession also protects a single ID from silently changing its TTL.
func SameSession(a, b SessionSpec) bool {
	return a.ID == b.ID && a.TTL == b.TTL
}
