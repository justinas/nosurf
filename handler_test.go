package nosurf

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDefaultFailureHandler(t *testing.T) {
	writer := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "http://doesntmatter.com/", nil)

	if err != nil {
		t.Fatal(err)
	}

	defaultFailureHandler(writer, req)

	if writer.Code != FailureCode {
		t.Errorf("Wrong status code for defaultFailure Handler: "+
			"expected %d, got %d", FailureCode, writer.Code)
	}
}
