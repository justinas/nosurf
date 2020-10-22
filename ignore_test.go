package nosurf

import (
	"net/http"
	"testing"
)

func TestIgnorePath(t *testing.T) {
	// the handler doesn't matter here, let's use nil
	hand := New(nil)
	path := "/home"
	exempt, _ := http.NewRequest("GET", path, nil)

	hand.IgnorePath(path)
	if !hand.IsIgnored(exempt) {
		t.Errorf("%v is not exempt, but it should be", exempt.URL.Path)
	}

	other, _ := http.NewRequest("GET", "/faq", nil)
	if hand.IsIgnored(other) {
		t.Errorf("%v is exempt, but it shouldn't be", other.URL.Path)
	}
}
