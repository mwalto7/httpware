package httpware

import (
	"fmt"
	"net/http"
)

// BasicAuthOptions represents the configurable settings of BasicAuth.
type BasicAuthOptions struct {
	// The name of the protected scope. Defaults to "Restricted".
	Realm string

	// A function used to validate a request's credentials.
	AuthFunc func(username, password string, r *http.Request) bool

	// Specifies is empty passwords are allowed.
	AllowEmptyPassword bool

	// Specifies if credentials can be parsed from the request URL.
	AllowURLCredentials bool

	// An http.Handler for unauthorized (401) requests. The default handler calls
	// http.Error with status code 401 and writes http.StatusText to the body.
	Unauthorized http.Handler

	// An http.Handler for forbidden (403) requests. The default handler calls
	// http.Error with status code 403 and writes http.StatusText to the body.
	Forbidden http.Handler
}

// BasicAuth enforces the HTTP Basic Authentication Scheme for an http.Handler.
//
// The credentials are parsed either from the Authorization header or the URL.
// By default, URL credentials are not allowed. To allow URL credentials, set
// BasicAuthOptions.AllowURLCredentials to true. Only one method should be
// used at a time. If both are set, the Authorization header takes precedence.
//
// See https://tools.ietf.org/html/rfc7617 for details about the auth scheme.
func BasicAuth(opts BasicAuthOptions) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return basicAuth{h: h, opts: opts}
	}
}

type basicAuth struct {
	h    http.Handler
	opts BasicAuthOptions
}

func (a basicAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var username, password string
	var ok bool
	switch {
	case r.Header.Get("Authorization") == "" && a.opts.AllowURLCredentials:
		username = r.URL.User.Username()
		password, ok = r.URL.User.Password()
		if !ok && a.opts.AllowURLCredentials {
			ok = true
		}
	default:
		username, password, ok = r.BasicAuth()
	}
	if !ok || username == "" || (!a.opts.AllowEmptyPassword && password == "") {
		a.unauthorized(w, r)
		return
	}
	if !a.opts.AuthFunc(username, password, r) {
		a.forbidden(w, r)
		return
	}
	a.h.ServeHTTP(w, r)
}

func (a basicAuth) unauthorized(w http.ResponseWriter, r *http.Request) {
	if a.opts.Unauthorized != nil {
		a.opts.Unauthorized.ServeHTTP(w, r)
		return
	}
	if a.opts.Realm == "" {
		a.opts.Realm = "Restricted"
	}
	w.Header().Add("WWW-Authenticate", fmt.Sprintf(`Basic realm=%q, charset="utf-8"`, a.opts.Realm))
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}

func (a basicAuth) forbidden(w http.ResponseWriter, r *http.Request) {
	if a.opts.Forbidden != nil {
		a.opts.Forbidden.ServeHTTP(w, r)
		return
	}
	http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
}

func bearerAuth() func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			panic("implement me")
		})
	}
}

func digestAuth() func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			panic("implement me")
		})
	}
}

func hobaAuth() func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			panic("implement me")
		})
	}
}

func mutualAuth() func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			panic("implement me")
		})
	}
}

func aWS4Auth() func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			panic("implement me")
		})
	}
}
