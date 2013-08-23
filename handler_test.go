package nosurf

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDefaultFailureHandler(t *testing.T) {
	writer := httptest.NewRecorder()
	req := dummyGet()

	defaultFailureHandler(writer, req)

	if writer.Code != FailureCode {
		t.Errorf("Wrong status code for defaultFailure Handler: "+
			"expected %d, got %d", FailureCode, writer.Code)
	}
}

func TestRegenerateTokenWorks(t *testing.T) {
	hand := New(http.HandlerFunc(defaultFailureHandler))
	writer := httptest.NewRecorder()

	req := dummyGet()
	token := hand.RegenerateToken(writer, req)

	header := writer.Header().Get("Set-Cookie")
	expected_part := fmt.Sprintf("csrf_token=%s;", token)

	if !strings.Contains(header, expected_part) {
		t.Errorf("Expected header to contain %v, it doesn't. The header is %v.",
			expected_part, header)
	}
}
