// +build !go1.7

package nosurf

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestClearsContextAfterTheRequest(t *testing.T) {
	hand := New(http.HandlerFunc(succHand))
	writer := httptest.NewRecorder()
	req := dummyGet()

	hand.ServeHTTP(writer, req)

	if contextMap[req] != nil {
		t.Errorf("The context entry should have been cleared after the request.")
		t.Errorf("Instead, the context entry remains: %v", contextMap[req])
	}
}

func TestNoDoubleCookie(t *testing.T) {
	var n *CSRFHandler
	n = New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.RegenerateToken(w, r)
	}))

	r := &http.Request{Method: "GET", URL: &url.URL{
		Scheme: "http",
		Host:   "dummy.us",
		Path:   "/",
	}}
	w := httptest.NewRecorder()

	n.ServeHTTP(w, r)

	count := strings.Count(w.HeaderMap.Get("Set-Cookie"), "csrf_token")
	if count > 1 {
		t.Errorf("Expected one CSRF cookie, got %d", count)
	}
}
