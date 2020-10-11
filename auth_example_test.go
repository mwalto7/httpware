package httpware_test

import (
	"net/http"

	"github.com/mwalto7/httpware"
)

func ExampleBasicAuth() {
	auth := httpware.BasicAuth(httpware.BasicAuthOptions{
		Realm: "My super secret path.",
		AuthFunc: func(username, password string, _ *http.Request) bool {
			return username == "user" && password == "pass"
		},
	})
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	http.Handle("/foo", auth(h))
	http.ListenAndServe(":8080", nil)
}
