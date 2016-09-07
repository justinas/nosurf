// +build !go1.7

package nosurf

import (
	"net/http"
	"net/http/httptest"
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
