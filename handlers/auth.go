package handlers

import (
	"database/sql"
	"html/template"
	"net/http"
	_ "github.com/mattn/go-sqlite3"
)

var (
	db   *sql.DB
	tmpl *template.Template
)

// User represents a registered user
type User struct {
	ID       int
	Username string
	Password string
	IsAdmin  bool
}

// TemplateData holds data for template rendering
type TemplateData struct {
	Error string
}

func InitDB(databasePath string) error {
	var err error
	db, err = sql.Open("sqlite3", databasePath)
	if err != nil {
		return err
	}

	// Create users table if it doesn't exist
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL,
		is_admin BOOLEAN DEFAULT FALSE
	);`
	_, err = db.Exec(createTableSQL)
	if err != nil {
		return err
	}

	return nil
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

		var user User
		err := db.QueryRow("SELECT id, username, password, is_admin FROM users WHERE username = ?", username).
			Scan(&user.ID, &user.Username, &user.Password, &user.IsAdmin)
		if err != nil || user.Password != password {
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

		_, err := db.Exec("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)", username, password, false)
		if err != nil {
			data.Error = "Username already exists or registration failed"
			tmpl.ExecuteTemplate(w, "register.html", data)
			return
		}

		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
}