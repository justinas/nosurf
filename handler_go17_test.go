//go:build go1.7
// +build go1.7

package nosurf

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

type dummyKeyType struct{}

// Confusing test name. Tests that nosurf's context is accessible
// when a request with golang's context is passed into Token().
func TestContextIsAccessibleWithContext(t *testing.T) {
	succHand := func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(context.WithValue(r.Context(), dummyKeyType{}, "dummyval"))
		token := Token(r)
		if token == "" {
			t.Errorf("Token is inaccessible in the success handler")
		}
	}

	hand := New(http.HandlerFunc(succHand))

	// we need a request that passes. Let's just use a safe method for that.
	req := dummyGet()
	writer := httptest.NewRecorder()

	hand.ServeHTTP(writer, req)
}

func TestNoDoubleCookie(t *testing.T) {
	var n *CSRFHandler
	n = New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.RegenerateToken(w, r)
	}))

	r := httptest.NewRequest("GET", "http://dummy.us", nil)
	w := httptest.NewRecorder()

	n.ServeHTTP(w, r)

	count := len(w.Result().Cookies())
	if count > 1 {
		t.Errorf("Expected one CSRF cookie, got %d", count)
	}
}
