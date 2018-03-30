package nosurf

import (
	"io"
	"mime/multipart"
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

	expectedBody := http.StatusText(FailureCode) + "\n"
	actualBody := writer.Body.String()
	if actualBody != expectedBody {
		t.Errorf("Wrong response body for defaultFailure Handler: "+
			"expected %q, got %q", expectedBody, actualBody)
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

func TestExemptedPass(t *testing.T) {
	handler := New(http.HandlerFunc(succHand))
	handler.ExemptPath("/faq")

	req, err := http.NewRequest("POST", "http://dummy.us/faq", strings.NewReader("a=b"))
	if err != nil {
		t.Fatal(err)
	}

	writer := httptest.NewRecorder()
	handler.ServeHTTP(writer, req)

	expected := 200

	if writer.Code != expected {
		t.Errorf("An exempted URL didn't pass the CSRF check."+
			"Expected HTTP status %d, got %d", expected, writer.Code)
	}

	writer.Flush()
}

func TestManualVerify(t *testing.T) {
	var keepToken string
	hand := New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			if !VerifyToken(Token(r), keepToken) {
				http.Error(w, "error", http.StatusBadRequest)
			}
		} else {
			keepToken = Token(r)
		}
	}))
	hand.ExemptPath("/")
	hand.SetFailureHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("Test failed. Reason: %v", Reason(r))
	}))

	server := httptest.NewServer(hand)
	defer server.Close()

	// issue the first request to get the token
	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	cookie := getRespCookie(resp, CookieName)
	if cookie == nil {
		t.Fatal("Cookie was not found in the response.")
	}

	// finalToken := b64encode(maskToken(b64decode(cookie.Value)))

	vals := [][]string{
		{"name", "Jolene"},
	}

	// Test usual POST
	{
		req, err := http.NewRequest("POST", server.URL, formBodyR(vals))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(cookie)

		resp, err = http.DefaultClient.Do(req)

		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 200 {
			t.Errorf("The request should have succeeded, but it didn't. Instead, the code was %d",
				resp.StatusCode)
		}
	}
}

// Tests that the token/reason context is accessible
// in the success/failure handlers
func TestContextIsAccessible(t *testing.T) {
	// case 1: success
	succHand := func(w http.ResponseWriter, r *http.Request) {
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

func TestEmptyRefererFails(t *testing.T) {
	hand := New(http.HandlerFunc(succHand))
	fhand := correctReason(t, ErrNoReferer)
	hand.SetFailureHandler(fhand)

	req, err := http.NewRequest("POST", "https://dummy.us/", strings.NewReader("a=b"))
	if err != nil {
		t.Fatal(err)
	}
	writer := httptest.NewRecorder()

	hand.ServeHTTP(writer, req)

	if writer.Code != FailureCode {
		t.Errorf("A POST request with no Referer should have failed with the code %d, but it didn't.",
			writer.Code)
	}
}

func TestDifferentOriginRefererFails(t *testing.T) {
	hand := New(http.HandlerFunc(succHand))
	fhand := correctReason(t, ErrBadReferer)
	hand.SetFailureHandler(fhand)

	req, err := http.NewRequest("POST", "https://dummy.us/", strings.NewReader("a=b"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Referer", "http://attack-on-golang.com")
	writer := httptest.NewRecorder()

	hand.ServeHTTP(writer, req)

	if writer.Code != FailureCode {
		t.Errorf("A POST request with a Referer from a different origin"+
			"should have failed with the code %d, but it didn't.", writer.Code)
	}
}

func TestNoTokenFails(t *testing.T) {
	hand := New(http.HandlerFunc(succHand))
	fhand := correctReason(t, ErrBadToken)
	hand.SetFailureHandler(fhand)

	vals := [][]string{
		{"name", "Jolene"},
	}

	req, err := http.NewRequest("POST", "http://dummy.us", formBodyR(vals))
	if err != nil {
		panic(err)
	}
	writer := httptest.NewRecorder()

	hand.ServeHTTP(writer, req)

	if writer.Code != FailureCode {
		t.Errorf("The check should've failed with the code %d, but instead, it"+
			" returned code %d", FailureCode, writer.Code)
	}

	expectedContentType := "text/plain; charset=utf-8"
	actualContentType := writer.Header().Get("Content-Type")
	if actualContentType != expectedContentType {
		t.Errorf("The check should've failed with content type %s, but instead, it"+
			" returned content type %s", expectedContentType, actualContentType)
	}
}

func TestWrongTokenFails(t *testing.T) {
	hand := New(http.HandlerFunc(succHand))
	fhand := correctReason(t, ErrBadToken)
	hand.SetFailureHandler(fhand)

	vals := [][]string{
		{"name", "Jolene"},
		// this won't EVER be a valid value with the current scheme
		{FormFieldName, "$#%^&"},
	}

	req, err := http.NewRequest("POST", "http://dummy.us", formBodyR(vals))
	if err != nil {
		panic(err)
	}
	writer := httptest.NewRecorder()

	hand.ServeHTTP(writer, req)

	if writer.Code != FailureCode {
		t.Errorf("The check should've failed with the code %d, but instead, it"+
			" returned code %d", FailureCode, writer.Code)
	}

	expectedContentType := "text/plain; charset=utf-8"
	actualContentType := writer.Header().Get("Content-Type")
	if actualContentType != expectedContentType {
		t.Errorf("The check should've failed with content type %s, but instead, it"+
			" returned content type %s", expectedContentType, actualContentType)
	}
}

func TestCustomCookieName(t *testing.T) {
	hand := New(http.HandlerFunc(succHand))

	if hand.getCookieName() != CookieName {
		t.Errorf("No base cookie set, expected CookieName to be %s, was %s", CookieName, hand.getCookieName())
	}

	hand.SetBaseCookie(http.Cookie{})

	if hand.getCookieName() != CookieName {
		t.Errorf("Base cookie with empty name set, expected CookieName to be %s, was %s", CookieName, hand.getCookieName())
	}

	customCookieName := "my_custom_cookie"
	hand.SetBaseCookie(http.Cookie{
		Name: customCookieName,
	})

	if hand.getCookieName() != customCookieName {
		t.Errorf("Base cookie with name %s was set, but CookieName was %s instead", customCookieName, hand.getCookieName())
	}
}

// For this and similar tests we start a test server
// Since it's much easier to get the cookie
// from a normal http.Response than from the recorder
func TestCorrectTokenPasses(t *testing.T) {
	hand := New(http.HandlerFunc(succHand))
	hand.SetFailureHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("Test failed. Reason: %v", Reason(r))
	}))

	server := httptest.NewServer(hand)
	defer server.Close()

	// issue the first request to get the token
	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	cookie := getRespCookie(resp, CookieName)
	if cookie == nil {
		t.Fatal("Cookie was not found in the response.")
	}

	finalToken := b64encode(maskToken(b64decode(cookie.Value)))

	vals := [][]string{
		{"name", "Jolene"},
		{FormFieldName, finalToken},
	}

	// Test usual POST
	/*
		{
			req, err := http.NewRequest("POST", server.URL, formBodyR(vals))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.AddCookie(cookie)

			resp, err = http.DefaultClient.Do(req)

			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != 200 {
				t.Errorf("The request should have succeeded, but it didn't. Instead, the code was %d",
					resp.StatusCode)
			}
		}
	*/

	// Test multipart
	{
		prd, pwr := io.Pipe()
		wr := multipart.NewWriter(pwr)
		go func() {

			for _, v := range vals {
				wr.WriteField(v[0], v[1])
			}

			err := wr.Close()
			if err != nil {
				t.Fatal(err)
			}
			err = pwr.Close()
			if err != nil {
				t.Fatal(err)
			}
		}()

		// Prepare a multipart request
		req, err := http.NewRequest("POST", server.URL, prd)
		if err != nil {
			t.Fatal(err)
		}

		req.Header.Add("Content-Type", wr.FormDataContentType())
		req.AddCookie(cookie)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 200 {
			t.Errorf("The request should have succeeded, but it didn't. Instead, the code was %d",
				resp.StatusCode)
		}
	}
}

func TestPrefersHeaderOverFormValue(t *testing.T) {
	// Let's do a nice trick to find out this:
	// We'll set the correct token in the header
	// And a wrong one in the form.
	// That way, if it succeeds,
	// it will mean that it prefered the header.

	hand := New(http.HandlerFunc(succHand))

	server := httptest.NewServer(hand)
	defer server.Close()

	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	cookie := getRespCookie(resp, CookieName)
	if cookie == nil {
		t.Fatal("Cookie was not found in the response.")
	}

	finalToken := b64encode(maskToken(b64decode(cookie.Value)))

	vals := [][]string{
		{"name", "Jolene"},
		{FormFieldName, "a very wrong value"},
	}

	req, err := http.NewRequest("POST", server.URL, formBodyR(vals))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set(HeaderName, finalToken)
	req.AddCookie(cookie)

	resp, err = http.DefaultClient.Do(req)

	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("The request should have succeeded, but it didn't. Instead, the code was %d",
			resp.StatusCode)
	}
}

func TestAddsVaryCookieHeader(t *testing.T) {
	hand := New(http.HandlerFunc(succHand))
	writer := httptest.NewRecorder()
	req := dummyGet()

	hand.ServeHTTP(writer, req)

	if !sContains(writer.Header()["Vary"], "Cookie") {
		t.Errorf("CSRFHandler didn't add a `Vary: Cookie` header.")
	}
}
