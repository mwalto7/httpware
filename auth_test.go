package httpware

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestBasicAuth(t *testing.T) {
	tests := []struct {
		name string
		opts BasicAuthOptions
		req  *http.Request
		resp *http.Response
	}{
		{
			name: "EmptyUserPassAuthorization",
			req:  basicAuthRequest("", "", false),
			resp: basicAuthResponse(http.StatusUnauthorized, "Restricted", http.StatusText(http.StatusUnauthorized)),
		},
		{
			name: "EmptyPassAuthorization",
			req:  basicAuthRequest("user", "", false),
			resp: basicAuthResponse(http.StatusUnauthorized, "Restricted", http.StatusText(http.StatusUnauthorized)),
		},
		{
			name: "EmptyUserAuthorization",
			req:  basicAuthRequest("", "pass", false),
			resp: basicAuthResponse(http.StatusUnauthorized, "Restricted", http.StatusText(http.StatusUnauthorized)),
		},
		{
			name: "UnauthorizedAuthorizationCustom",
			opts: BasicAuthOptions{
				AuthFunc:     func(string, string, *http.Request) bool { return false },
				Unauthorized: http.HandlerFunc(basicAuth{}.unauthorized),
			},
			req:  basicAuthRequest("", "", false),
			resp: basicAuthResponse(http.StatusUnauthorized, "Restricted", http.StatusText(http.StatusUnauthorized)),
		},
		{
			name: "ForbiddenAuthorization",
			opts: BasicAuthOptions{AuthFunc: func(string, string, *http.Request) bool { return false }},
			req:  basicAuthRequest("user", "pass", false),
			resp: basicAuthResponse(http.StatusForbidden, "", http.StatusText(http.StatusForbidden)),
		},
		{
			name: "ForbiddenAuthorizationCustom",
			opts: BasicAuthOptions{
				AuthFunc:  func(string, string, *http.Request) bool { return false },
				Forbidden: http.HandlerFunc(basicAuth{}.forbidden),
			},
			req:  basicAuthRequest("user", "pass", false),
			resp: basicAuthResponse(http.StatusForbidden, "", http.StatusText(http.StatusForbidden)),
		},
		{
			name: "OKAuthorization",
			opts: BasicAuthOptions{AuthFunc: func(string, string, *http.Request) bool { return true }},
			req:  basicAuthRequest("user", "pass", false),
			resp: basicAuthResponse(http.StatusOK, "", ""),
		},
		{
			name: "OKEmptyPasswordAuthorization",
			opts: BasicAuthOptions{
				AllowEmptyPassword: true,
				AuthFunc:           func(string, string, *http.Request) bool { return true },
			},
			req:  basicAuthRequest("user", "", false),
			resp: basicAuthResponse(http.StatusOK, "", ""),
		},
		{
			name: "EmptyUserPassURL",
			opts: BasicAuthOptions{AllowURLCredentials: true},
			req:  basicAuthRequest("", "", true),
			resp: basicAuthResponse(http.StatusUnauthorized, "Restricted", http.StatusText(http.StatusUnauthorized)),
		},
		{
			name: "EmptyPassURL",
			opts: BasicAuthOptions{AllowURLCredentials: true},
			req:  basicAuthRequest("user", "", true),
			resp: basicAuthResponse(http.StatusUnauthorized, "Restricted", http.StatusText(http.StatusUnauthorized)),
		},
		{
			name: "EmptyUserURL",
			opts: BasicAuthOptions{AllowURLCredentials: true},
			req:  basicAuthRequest("", "pass", true),
			resp: basicAuthResponse(http.StatusUnauthorized, "Restricted", http.StatusText(http.StatusUnauthorized)),
		},
		{
			name: "UnauthorizedURLCustom",
			opts: BasicAuthOptions{
				AllowURLCredentials: true,
				AuthFunc:            func(string, string, *http.Request) bool { return false },
				Unauthorized:        http.HandlerFunc(basicAuth{}.unauthorized),
			},
			req:  basicAuthRequest("", "", true),
			resp: basicAuthResponse(http.StatusUnauthorized, "Restricted", http.StatusText(http.StatusUnauthorized)),
		},
		{
			name: "ForbiddenURLCustom",
			opts: BasicAuthOptions{
				AllowURLCredentials: true,
				AuthFunc:            func(string, string, *http.Request) bool { return false },
				Forbidden:           http.HandlerFunc(basicAuth{}.forbidden),
			},
			req:  basicAuthRequest("user", "pass", true),
			resp: basicAuthResponse(http.StatusForbidden, "", http.StatusText(http.StatusForbidden)),
		},
		{
			name: "ForbiddenURL",
			opts: BasicAuthOptions{
				AllowURLCredentials: true,
				AuthFunc:            func(string, string, *http.Request) bool { return false },
			},
			req:  basicAuthRequest("user", "pass", true),
			resp: basicAuthResponse(http.StatusForbidden, "", http.StatusText(http.StatusForbidden)),
		},
		{
			name: "OKURL",
			opts: BasicAuthOptions{
				AllowURLCredentials: true,
				AuthFunc:            func(string, string, *http.Request) bool { return true },
			},
			req:  basicAuthRequest("user", "pass", true),
			resp: basicAuthResponse(http.StatusOK, "", ""),
		},
		{
			name: "OKEmptyPasswordAuthorization",
			opts: BasicAuthOptions{
				AllowURLCredentials: true,
				AllowEmptyPassword:  true,
				AuthFunc:            func(string, string, *http.Request) bool { return true },
			},
			req:  basicAuthRequest("user", "", true),
			resp: basicAuthResponse(http.StatusOK, "", ""),
		},
		{
			name: "OKEmptyPasswordAuthorization",
			opts: BasicAuthOptions{
				AllowURLCredentials: true,
				AllowEmptyPassword:  true,
				AuthFunc:            func(string, string, *http.Request) bool { return true },
			},
			req:  httptest.NewRequest(http.MethodGet, "http://user@example.com", nil),
			resp: basicAuthResponse(http.StatusOK, "", ""),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			BasicAuth(tt.opts)(handleOK()).ServeHTTP(rec, tt.req)
			if got, want := rec.Code, tt.resp.StatusCode; got != want {
				t.Fatalf("status code: got %d, want %d", got, want)
			}
			for k := range tt.resp.Header {
				if got, want := rec.Header().Get(k), tt.resp.Header.Get(k); got != want {
					t.Errorf("%s: got %q, want %q", k, got, want)
				}
			}
			b, _ := ioutil.ReadAll(tt.resp.Body)
			if got, want := bytes.TrimSpace(rec.Body.Bytes()), bytes.TrimSpace(b); !bytes.Equal(got, want) {
				t.Fatalf("body: got %s, want %s", got, want)
			}
		})
	}
}

func basicAuthRequest(username, password string, inURL bool) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
	if inURL {
		r.URL.User = url.UserPassword(username, password)
	} else {
		r.SetBasicAuth(username, password)
	}
	return r
}

func basicAuthResponse(statusCode int, realm, body string) *http.Response {
	var r http.Response
	r.StatusCode = statusCode
	r.Header = make(http.Header)
	if statusCode == http.StatusUnauthorized {
		r.Header.Add("WWW-Authenticate", fmt.Sprintf(`Basic realm=%q, charset="utf-8"`, realm))
	}
	r.Body = ioutil.NopCloser(strings.NewReader(body))
	return &r
}

func handleOK() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}
}
