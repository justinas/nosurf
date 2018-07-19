package nosurf

import (
	"testing"
)

func TestTokenForRequestWithoutContext(t *testing.T) {
	req := dummyGet()
	token := Token(req)

	if token != "" {
		t.Errorf("Token should be %q but it's %v", "", token)
	}
}
