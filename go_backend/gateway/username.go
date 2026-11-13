package gateway

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultSessionTTL = 10 * time.Minute
	maxSessionTTL     = 24 * time.Hour
)

var (
	countryPattern = regexp.MustCompile(`^[A-Za-z]{2}$`)
	sessionPattern = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)
)

// Request is what a proxy username asks of the pool. An empty Session means
// rotating egress; TTL is only meaningful with a Session.
type Request struct {
	Country string
	Session string
	TTL     time.Duration
}

// ParseUsername accepts "<account>[-country-XX][-session-ID[-t-N]]" with the
// parameters in any order. The account is matched literally, so it may itself
// contain hyphens.
func ParseUsername(account, username string) (Request, error) {
	if username == account {
		return Request{}, nil
	}
	rest, found := strings.CutPrefix(username, account+"-")
	if !found || account == "" {
		return Request{}, errors.New("unknown proxy account")
	}
	parts := strings.Split(rest, "-")
	if len(parts)%2 != 0 {
		return Request{}, fmt.Errorf("parameters must be key-value pairs: %q", rest)
	}
	var request Request
	seen := make(map[string]bool, len(parts)/2)
	for i := 0; i < len(parts); i += 2 {
		key, value := strings.ToLower(parts[i]), parts[i+1]
		if seen[key] {
			return Request{}, fmt.Errorf("duplicate parameter %q", key)
		}
		seen[key] = true
		switch key {
		case "country":
			if !countryPattern.MatchString(value) {
				return Request{}, fmt.Errorf("country must be a two-letter code: %q", value)
			}
			request.Country = strings.ToUpper(value)
		case "session":
			if !sessionPattern.MatchString(value) {
				return Request{}, fmt.Errorf("session must be 1-64 letters, digits or underscores: %q", value)
			}
			request.Session = value
		case "t":
			minutes, err := strconv.Atoi(value)
			// Compare minutes, not durations: a huge value would overflow.
			if err != nil || minutes < 1 || minutes > int(maxSessionTTL/time.Minute) {
				return Request{}, fmt.Errorf("t must be 1-%d minutes: %q", int(maxSessionTTL/time.Minute), value)
			}
			request.TTL = time.Duration(minutes) * time.Minute
		default:
			return Request{}, fmt.Errorf("unknown parameter %q", key)
		}
	}
	if request.TTL != 0 && request.Session == "" {
		return Request{}, errors.New("t requires a session")
	}
	if request.Session != "" && request.TTL == 0 {
		request.TTL = DefaultSessionTTL
	}
	return request, nil
}
