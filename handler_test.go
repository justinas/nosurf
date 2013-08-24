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

func TestRegenerateToken(t *testing.T) {
	hand := New(nil)
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

// Kind of a duplication of TestRegenerateToken,
// but it's still good to test this too.
func TestsetTokenCookie(t *testing.T) {
	hand := New(nil)

	writer := httptest.NewRecorder()
	req := dummyGet()

	token := "dummy"
	hand.setTokenCookie(writer, req, token)

	header := writer.Header().Get("Set-Cookie")
	expected_part := fmt.Sprintf("csrf_token=%s;", token)

	if !strings.Contains(header, expected_part) {
		t.Errorf("Expected header to contain %v, it doesn't. The header is %v.",
			expected_part, header)
	}

	tokenInContext := Token(req)
	if tokenInContext != token {
		t.Errorf("RegenerateToken didn't set the token in the context map!"+
			" Expected %v, got %v", token, tokenInContext)
	}
}

func TestSafeMethodsPass(t *testing.T) {
	handler := New(http.HandlerFunc(succHand))

	for _, method := range safeMethods {
		req, err := http.NewRequest(method, "http://dummy.us", nil)

		if err != nil {
			t.Fatal(err)
		}

		writer := httptest.NewRecorder()
		handler.ServeHTTP(writer, req)

		expected := 200

		if writer.Code != expected {
			t.Errorf("A safe method didn't pass the CSRF check."+
				"Expected HTTP status %d, got %d", expected, writer.Code)
		}

		writer.Flush()
	}
}
