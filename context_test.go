package nosurf

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTokenForRequestWithoutContext(t *testing.T) {
	req := dummyGet()
	token := Token(req)

	if token != "" {
		t.Errorf("Token should be %q but it's %v", "", token)
	}
}

func TestTokenFromContextWithoutToken(t *testing.T) {
	token := TokenFromContext(context.Background())

	if token != "" {
		t.Errorf("Token should be %q but it's %v", "", token)
	}
}

func TestTokenFromContextMatchesToken(t *testing.T) {
	succHand := func(w http.ResponseWriter, r *http.Request) {
		if got, want := TokenFromContext(r.Context()), Token(r); got != want {
			t.Errorf("TokenFromContext returned %q, want %q", got, want)
		}
		if TokenFromContext(r.Context()) == "" {
			t.Errorf("TokenFromContext should not be empty inside the handler")
		}
	}

	hand := New(http.HandlerFunc(succHand))

	req := dummyGet()
	writer := httptest.NewRecorder()

	hand.ServeHTTP(writer, req)
}
