package handlers

import (
	"fmt"
	"net/http"
)

// HomeHandler handles the home page
func HomeHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	fmt.Fprintf(w, "Welcome to the Go Web Server!<br>"+
		"<a href='/login'>Login</a> | <a href='/register'>Register</a>")
}

// NotFoundHandler handles 404 errors
func NotFoundHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprintf(w, "404 - Page not found")
}
