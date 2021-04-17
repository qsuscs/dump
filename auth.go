package main

import (
	"net/http"
)

type basicAuthMiddleware struct {
	Users map[string]string
}

func (mw *basicAuthMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		userpass, exists := mw.Users[user]
		if !ok || !exists || pass != userpass {
			w.Header().Add("WWW-Authenticate", `Basic realm="protected"`)
			w.WriteHeader(http.StatusUnauthorized)
		} else {
			next.ServeHTTP(w, r)
		}
	})
}
