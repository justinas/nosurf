package nosurf

import (
	"net/http"
	"testing"
)

func dummyGet() *http.Request {
	req, err := http.NewRequest("GET", "http://dum.my/", nil)
	if err != nil {
		panic(err)
	}
	return req
}

func succHand(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(200)
	w.Write([]byte("success"))
}

// Returns a HandlerFunc
// that tests for the correct failure reason
func correctReason(t *testing.T, reason error) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		got := Reason(r)
		if got != reason {
			t.Errorf("CSRF check should have failed with the reason %#v,"+
				" but it failed with the reason %#v", reason, got)
		}
		// Writes the default failure code
		w.WriteHeader(FailureCode)
	}

	return http.HandlerFunc(fn)
}
