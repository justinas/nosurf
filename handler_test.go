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

func TestRefererHandling(t *testing.T) {
	const host = "example.com"
	var allowedOrigins = []string{"https://api.example.com", "http://example.org"}
	testCases := []struct {
		name         string
		isTLS        bool
		referer      string
		origin       string
		secFetchSite string
		expectReason error
	}{
		{
			name:         "no Referer nor Origin fails on secure requests",
			isTLS:        true,
			expectReason: ErrNoReferer,
		},
		{
			name:         "identical secure Referer passes",
			isTLS:        true,
			referer:      "https://example.com",
			expectReason: nil,
		},
		{
			name:         "differing Referer fails when Origin is absent",
			isTLS:        true,
			referer:      "https://attacker.lol",
			expectReason: ErrBadReferer,
		},
		{
			name:         "mismatched Referer scheme fails when Origin is absent",
			isTLS:        true,
			referer:      "http://example.com",
			expectReason: ErrBadReferer,
		},
		{
			name:         "mismatched Referer fails on insecure requests",
			isTLS:        false,
			referer:      "https://attacker.lol",
			expectReason: ErrBadReferer,
		},
		{
			name:         "mismatched Origin fails on insecure requests",
			isTLS:        false,
			origin:       "http://attacker.lol",
			expectReason: ErrBadOrigin,
		},
		{
			name:         "mismatched Origin fails on secure requests",
			isTLS:        false,
			origin:       "http://attacker.lol",
			referer:      "https://example.com",
			expectReason: ErrBadOrigin,
		},
		{
			name:         "mismatched Origin scheme fails on insecure requests",
			isTLS:        false,
			origin:       "https://example.com",
			expectReason: ErrBadOrigin,
		},
		{
			name:         "mismatched Origin scheme fails on insecure requests",
			isTLS:        true,
			origin:       "http://example.com",
			expectReason: ErrBadOrigin,
		},
		{
			name:         "matching Origin passes on insecure requests",
			isTLS:        false,
			origin:       "http://example.com",
			expectReason: nil,
		},
		{
			name:         "matching Origin passes on secure requests",
			isTLS:        true,
			origin:       "https://example.com",
			expectReason: nil,
		},
		{
			name:         "explicitly allowed insecure Origin passes",
			isTLS:        false,
			origin:       "http://example.org",
			referer:      "http://attacker.lol",
			expectReason: nil,
		},
		{
			name:         "explicitly allowed insecure Origin passes, despite a secure request",
			isTLS:        false,
			origin:       "http://example.org",
			referer:      "http://attacker.lol",
			expectReason: nil,
		},
		{
			name:         "explicitly allowed secure Origin passes",
			isTLS:        true,
			origin:       "https://api.example.com",
			referer:      "http://attacker.lol",
			expectReason: nil,
		},
		{
			name:         "explicitly allowed insecure Origin passes, despite an insecure request",
			isTLS:        false,
			origin:       "https://api.example.com",
			referer:      "http://attacker.lol",
			expectReason: nil,
		},
		{
			name:         "explicitly allowed Referer passes when Origin is absent",
			isTLS:        true,
			referer:      "http://example.org",
			expectReason: nil,
		},
		{
			name:         "Sec-Fetch-Site: same-origin is sufficient",
			isTLS:        true,
			secFetchSite: "same-origin",
			expectReason: nil,
		},
		{
			name:         "Sec-Fetch-Site: same-site does not pass",
			isTLS:        true,
			secFetchSite: "same-site",
			expectReason: ErrNoReferer,
		},
		{
			name:         "Sec-Fetch-Site: none does not pass",
			isTLS:        true,
			secFetchSite: "null",
			expectReason: ErrNoReferer,
		},
		{
			name:         "no origin headers present, secure request does not pass",
			isTLS:        true,
			expectReason: ErrNoReferer,
		},
		{
			name:         "no origin headers present, insecure request does not pass",
			isTLS:        false,
			expectReason: ErrNoReferer,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hand := New(http.HandlerFunc(succHand))
			fhand := correctReason(t, tc.expectReason)
			hand.SetFailureHandler(fhand)
			hand.SetIsTLSFunc(func(_ *http.Request) bool { return tc.isTLS })
			origins, err := StaticOrigins(allowedOrigins...)
			if err != nil {
				t.Fatal(err)
			}
			hand.SetIsAllowedOriginFunc(origins)

			server := httptest.NewServer(hand)
			t.Cleanup(func() { server.Close() })

			// Issue a GET to fetch the token
			req, err := http.NewRequest(http.MethodGet, server.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Host = host

			resp, err := server.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			cookie := getRespCookie(resp, CookieName)

			// Issue POST to check handling
			finalToken := b64encode(maskToken(b64decode(cookie.Value)))
			req, err = http.NewRequest("POST", server.URL, formBodyR([][]string{
				{"name", "Jolene"},
				{FormFieldName, finalToken},
			}))
			if err != nil {
				t.Fatal(err)
			}
			req.Host = host
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tc.referer != "" {
				req.Header.Set("Referer", tc.referer)
			}
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.secFetchSite != "" {
				req.Header.Set("Sec-Fetch-Site", tc.secFetchSite)
			}
			req.AddCookie(cookie)
			resp, err = server.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}

			if tc.expectReason == nil {
				if resp.StatusCode != http.StatusOK {
					t.Errorf("Expected request to succeed, but it failed with code %d", resp.StatusCode)
				}
			} else if resp.StatusCode != FailureCode {
				t.Errorf("Expected request to fail with status code %d, but the status code was %d", FailureCode, resp.StatusCode)
			}
		})
	}
}

func TestNoTokenFails(t *testing.T) {
	hand := New(http.HandlerFunc(succHand))
	fhand := correctReason(t, ErrBadToken)
	hand.SetFailureHandler(fhand)

	vals := [][]string{
		{"name", "Jolene"},
	}

	req, err := http.NewRequest("POST", "/", formBodyR(vals))
	if err != nil {
		panic(err)
	}
	req.Host = "example.com"
	req.Header.Add("Referer", "https://example.com")
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

	req, err := http.NewRequest("POST", "/", formBodyR(vals))
	if err != nil {
		panic(err)
	}
	req.Host = "example.com"
	req.Header.Add("Referer", "https://example.com")
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
	{
		req, err := http.NewRequest("POST", server.URL, formBodyR(vals))
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "example.com"
		req.Header.Add("Referer", "https://example.com")
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

	// Test multipart
	{
		prd, pwr := io.Pipe()
		wr := multipart.NewWriter(pwr)
		go func() {

			for _, v := range vals {
				err := wr.WriteField(v[0], v[1])
				if err != nil {
					t.Error(err)
					return
				}
			}

			err := wr.Close()
			if err != nil {
				t.Error(err)
				return
			}
			err = pwr.Close()
			if err != nil {
				t.Error(err)
			}
		}()

		// Prepare a multipart request
		req, err := http.NewRequest("POST", server.URL, prd)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "example.com"
		req.Header.Add("Referer", "https://example.com")
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
	req.Host = "example.com"
	req.Header.Add("Referer", "https://example.com")
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

func TestRegenerateTokenReplacesCookieWhenMissing(t *testing.T) {
	var got string
	var hand *CSRFHandler
	hand = New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = hand.RegenerateToken(w, r)
	}))

	writer := httptest.NewRecorder()
	hand.ServeHTTP(writer, dummyGet())

	cookies := writer.Result().Cookies()
	var csrf []*http.Cookie
	for _, c := range cookies {
		if c.Name == CookieName {
			csrf = append(csrf, c)
		}
	}
	if len(csrf) != 1 {
		t.Fatalf("expected 1 %s cookie after RegenerateToken with no incoming cookie, got %d: %v",
			CookieName, len(csrf), writer.Header()["Set-Cookie"])
	}
	if got == "" {
		t.Fatal("RegenerateToken returned an empty token")
	}
	if TokenFromCookie := b64decode(csrf[0].Value); len(TokenFromCookie) != tokenLength {
		t.Fatalf("cookie token has length %d, want %d", len(TokenFromCookie), tokenLength)
	}
}
