package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"net/http"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

func main() {
	// Conexão com o banco de dados SQLite
	var err error
	db, err = sql.Open("sqlite3", "./database.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	// Criação da tabela de usuários, se não existir (sem o campo email)
	createUsersTable := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL
	);`
	_, err = db.Exec(createUsersTable)
	if err != nil {
		panic(err)
	}

	// Criação da tabela de admins, se não existir
	createAdminsTable := `
	CREATE TABLE IF NOT EXISTS admins (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL
	);`
	_, err = db.Exec(createAdminsTable)
	if err != nil {
		panic(err)
	}

	// Configuração do servidor de arquivos estáticos
	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	// Rotas
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/admin", adminHandler)
	http.HandleFunc("/camisas", camisasHandler)
	http.HandleFunc("/canecas", canecasHandler)
	http.HandleFunc("/registrar", registrarHandler)

	fmt.Println("Servidor rodando em http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/index.html")
	if err != nil {
		http.Error(w, "Erro ao carregar a página inicial", http.StatusInternalServerError)
		return
	}
	message := r.URL.Query().Get("message")
	data := struct {
		Message string
	}{
		Message: message,
	}
	tmpl.Execute(w, data)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		tmpl, err := template.ParseFiles("templates/login.html")
		if err != nil {
			http.Error(w, "Erro ao carregar a página de login", http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, nil)
		return
	}

	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")

		// Buscar usuário no banco de dados
		var storedPassword string
		err := db.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&storedPassword)
		if err == sql.ErrNoRows {
			http.Error(w, "Usuário não encontrado", http.StatusBadRequest)
			return
		}
		if err != nil {
			http.Error(w, "Erro ao buscar usuário", http.StatusInternalServerError)
			return
		}

		// Verificar senha
		err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(password))
		if err != nil {
			http.Error(w, "Senha incorreta", http.StatusBadRequest)
			return
		}

		// Redirecionar para a página inicial com mensagem de sucesso
		http.Redirect(w, r, "/?message=Login+realizado+com+sucesso", http.StatusSeeOther)
		return
	}
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		tmpl, err := template.ParseFiles("templates/admin.html")
		if err != nil {
			http.Error(w, "Erro ao carregar a página de admin", http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, nil)
		return
	}

	if r.Method == "POST" {
		username := r.FormValue("admin_username")
		password := r.FormValue("admin_password")

		// Buscar admin no banco de dados
		var storedPassword string
		err := db.QueryRow("SELECT password FROM admins WHERE username = ?", username).Scan(&storedPassword)
		if err == sql.ErrNoRows {
			http.Error(w, "Usuário admin não encontrado", http.StatusBadRequest)
			return
		}
		if err != nil {
			http.Error(w, "Erro ao buscar usuário admin", http.StatusInternalServerError)
			return
		}

		// Verificar senha
		err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(password))
		if err != nil {
			http.Error(w, "Senha incorreta para admin", http.StatusBadRequest)
			return
		}

		// Redirecionar para a página inicial com mensagem de sucesso
		http.Redirect(w, r, "/?message=Login+admin+realizado+com+sucesso", http.StatusSeeOther)
		return
	}
}

func camisasHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/camisas.html")
	if err != nil {
		http.Error(w, "Erro ao carregar a página de camisas", http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, nil)
}

func canecasHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/canecas.html")
	if err != nil {
		http.Error(w, "Erro ao carregar a página de canecas", http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, nil)
}

func registrarHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		tmpl, err := template.ParseFiles("templates/registrar.html")
		if err != nil {
			http.Error(w, "Erro ao carregar a página de registro", http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, nil)
		return
	}

	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")
		confirmPassword := r.FormValue("confirm_password")

		// Verificar se as senhas coincidem
		if password != confirmPassword {
			http.Error(w, "Erro ao registrar: as senhas não coincidem", http.StatusBadRequest)
			return
		}

		// Criptografar a senha
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Erro ao processar o registro", http.StatusInternalServerError)
			return
		}

		// Inserir no banco de dados (sem email)
		_, err = db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", username, hashedPassword)
		if err != nil {
			http.Error(w, "Erro ao registrar: usuário já existe", http.StatusBadRequest)
			return
		}

		// Redirecionar para a página inicial com mensagem de sucesso
		http.Redirect(w, r, "/?message=Registro+realizado+com+sucesso", http.StatusSeeOther)
		return
	}
}