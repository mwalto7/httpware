# httpware [![PkgGoDev](https://pkg.go.dev/badge/github.com/mwalto7/httpware)](https://pkg.go.dev/github.com/mwalto7/httpware) [![Go Report Card](https://goreportcard.com/badge/github.com/mwalto7/httpware)](https://goreportcard.com/report/github.com/mwalto7/httpware) ![Test](https://github.com/mwalto7/httpware/workflows/Test/badge.svg?branch=main)

A collection of useful Go HTTP middleware functions.

```bash
go get github.com/mwalto7/httpware
```

## Authentication

Need HTTP Basic Auth for your routes? Simply wrap your handlers with `httpware.BasicAuth`:

```go
package main

import (
    "fmt"
    "net/http"

    "github.com/mwalto7/httpware"
)

func main() {
    authenticate := httpware.BasicAuth(httpware.BasicAuthOptions{
        Realm: "My super secure path.",
        AuthFunc: func(username, password string, _ *http.Request) bool {
            // Don't do this in production.
            return username == "user" && password == "pass"
        },
    })
    mux := http.NewServeMux()
    mux.Handle("/foo", authenticate(handleFoo()))
    _ = http.ListenAndServe(":8080", mux)
}

func handleFoo() http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        w.Header().Add("Content-Type", "text/plain")
        w.WriteHeader(http.StatusOK)
        _, _ = fmt.Fprintln(w, "You're authenticated 🙂") 
    }
}
```
