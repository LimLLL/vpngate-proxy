package gateway

import (
	"testing"
	"time"
)

func TestParseUsername(t *testing.T) {
	for _, test := range []struct {
		username string
		want     Request
	}{
		{"acct", Request{}},
		{"acct-session-abc", Request{Session: "abc", TTL: 10 * time.Minute}},
		{"acct-session-abc-t-10", Request{Session: "abc", TTL: 10 * time.Minute}},
		{"acct-country-jp", Request{Country: "JP"}},
		{"acct-country-JP-session-a_1-t-1440", Request{Country: "JP", Session: "a_1", TTL: 24 * time.Hour}},
		{"acct-t-5-session-abc-country-us", Request{Country: "US", Session: "abc", TTL: 5 * time.Minute}},
	} {
		got, err := ParseUsername("acct", test.username)
		if err != nil || got != test.want {
			t.Errorf("%q: got %+v, %v; want %+v", test.username, got, err, test.want)
		}
	}
	hyphenated, err := ParseUsername("my-acct", "my-acct-session-x")
	if err != nil || hyphenated.Session != "x" {
		t.Errorf("hyphenated account: %+v %v", hyphenated, err)
	}
	for _, username := range []string{
		"", "other", "other-session-abc", "acctx-session-abc",
		"acct-", "acct-session", "acct-session-a-b", "acct-session-a.b",
		"acct-t-10", "acct-session-a-t-0", "acct-session-a-t-1441", "acct-session-a-t-99999999999999999",
		"acct-country-jpn", "acct-country-j1", "acct-session-a-session-b", "acct-region-x",
	} {
		if got, err := ParseUsername("acct", username); err == nil {
			t.Errorf("%q was accepted as %+v", username, got)
		}
	}
}
