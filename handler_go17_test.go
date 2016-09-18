// +build go1.7

package nosurf

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Confusing test name. Tests that nosurf's context is accessible
// when a request with golang's context is passed into Token().
func TestContextIsAccessibleWithContext(t *testing.T) {
	succHand := func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(context.WithValue(r.Context(), "dummykey", "dummyval"))
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
