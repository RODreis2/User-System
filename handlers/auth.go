package handlers

import (
	"html/template"
	"net/http"
	"sync"
)

var (
	users = make(map[string]User)
	mu    sync.RWMutex
	tmpl  *template.Template
)

// User represents a registered user
type User struct {
	Username string
	Password string
	IsAdmin  bool
}

// TemplateData holds data for template rendering
type TemplateData struct {
	Error string
}

func init() {
	var err error
	tmpl, err = template.ParseGlob("templates/*.html")
	if err != nil {
		panic(err)
	}
}

// AuthLoginHandler handles user login
func AuthLoginHandler(w http.ResponseWriter, r *http.Request) {
	data := TemplateData{}

	if r.Method == "GET" {
		tmpl.ExecuteTemplate(w, "login.html", data)
		return
	}

	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")

		mu.RLock()
		user, exists := users[username]
		mu.RUnlock()

		if !exists || user.Password != password {
			data.Error = "Invalid username or password"
			tmpl.ExecuteTemplate(w, "login.html", data)
			return
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
}

// AuthRegisterHandler handles user registration
func AuthRegisterHandler(w http.ResponseWriter, r *http.Request) {
	data := TemplateData{}

	if r.Method == "GET" {
		tmpl.ExecuteTemplate(w, "register.html", data)
		return
	}

	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")
		confirmPass := r.FormValue("confirm_password")

		if password != confirmPass {
			data.Error = "Passwords do not match"
			tmpl.ExecuteTemplate(w, "register.html", data)
			return
		}

		mu.RLock()
		_, exists := users[username]
		mu.RUnlock()

		if exists {
			data.Error = "Username already exists"
			tmpl.ExecuteTemplate(w, "register.html", data)
			return
		}

		mu.Lock()
		users[username] = User{
			Username: username,
			Password: password,
			IsAdmin:  false,
		}
		mu.Unlock()

		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
}
