package web

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecodeBodyProvidesStableRequestTypes(t *testing.T) {
	body := `{"port":"9000","limit":15,"username":"operator","countries":["JP","US"]}`
	request := httptest.NewRequest("POST", "http://localhost/api", strings.NewReader(body))
	values, err := decodeBody(request, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if values["port"].integer() != 9000 || values["limit"].integer() != 15 {
		t.Fatalf("port/limit parsing changed: %+v", values)
	}
	if values["username"].text() != "operator" {
		t.Fatalf("unexpected username: %q", values["username"].text())
	}
	countries := values["countries"].strings()
	if len(countries) != 2 || countries[0] != "JP" || countries[1] != "US" {
		t.Fatalf("unexpected countries: %v", countries)
	}
}
