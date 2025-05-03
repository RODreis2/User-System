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

type Product struct {
	ID          int
	Type        string
	Name        string
	Description string
}

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

	// Criação da tabela de produtos, se não existir
	createProductsTable := `
	CREATE TABLE IF NOT EXISTS products (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		type TEXT NOT NULL,
		name TEXT NOT NULL,
		description TEXT
	);`
	_, err = db.Exec(createProductsTable)
	if err != nil {
		panic(err)
	}

	// Criação da tabela de configurações, se não existir (para o número do WhatsApp)
	createSettingsTable := `
	CREATE TABLE IF NOT EXISTS settings (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		key TEXT UNIQUE NOT NULL,
		value TEXT NOT NULL
	);`
	_, err = db.Exec(createSettingsTable)
	if err != nil {
		panic(err)
	}

	// Adicionar um administrador padrão se não existir
	defaultAdminUsername := "admin"
	defaultAdminPassword := "admin123"
	var adminCount int
	err = db.QueryRow("SELECT COUNT(*) FROM admins WHERE username = ?", defaultAdminUsername).Scan(&adminCount)
	if err != nil {
		panic(err)
	}
	if adminCount == 0 {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(defaultAdminPassword), bcrypt.DefaultCost)
		if err != nil {
			panic(err)
		}
		_, err = db.Exec("INSERT INTO admins (username, password) VALUES (?, ?)", defaultAdminUsername, hashedPassword)
		if err != nil {
			panic(err)
		}
		fmt.Println("Administrador padrão criado: username=admin, password=admin123")
	} else {
		fmt.Println("Administrador padrão já existe.")
	}

	// Configuração do servidor de arquivos estáticos
	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	// Rotas
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/admin", adminHandler)
	http.HandleFunc("/admin/dashboard", adminDashboardHandler)
	http.HandleFunc("/admin/update_products", adminUpdateProductsHandler)
	http.HandleFunc("/admin/update_whatsapp", adminUpdateWhatsAppHandler)
	http.HandleFunc("/camisas", camisasHandler)
	http.HandleFunc("/canecas", canecasHandler)
	http.HandleFunc("/registrar", registrarHandler)
	http.HandleFunc("/whatsapp", whatsappHandler)

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

		// Redirecionar para o painel de administração
		http.Redirect(w, r, "/admin/dashboard", http.StatusSeeOther)
		return
	}
}

func adminDashboardHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		tmpl, err := template.ParseFiles("templates/admin_dashboard.html")
		if err != nil {
			http.Error(w, "Erro ao carregar o painel de admin", http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, nil)
		return
	}
}

func adminUpdateProductsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		productType := r.FormValue("product_type")
		productName := r.FormValue("product_name")
		productDescription := r.FormValue("product_description")

		// Inserir ou atualizar produto no banco de dados
		_, err := db.Exec("INSERT OR REPLACE INTO products (type, name, description) VALUES (?, ?, ?)", productType, productName, productDescription)
		if err != nil {
			http.Error(w, "Erro ao atualizar produto", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/admin/dashboard?message=Produto+atualizado+com+sucesso", http.StatusSeeOther)
		return
	}
	http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
}

func adminUpdateWhatsAppHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		whatsappNumber := r.FormValue("whatsapp_number")

		// Atualizar número do WhatsApp no banco de dados
		_, err := db.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", "whatsapp_number", whatsappNumber)
		if err != nil {
			http.Error(w, "Erro ao atualizar número do WhatsApp", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/admin/dashboard?message=Número+do+WhatsApp+atualizado+com+sucesso", http.StatusSeeOther)
		return
	}
	http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
}

func camisasHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/camisas.html")
	if err != nil {
		http.Error(w, "Erro ao carregar a página de camisas", http.StatusInternalServerError)
		return
	}

	rows, err := db.Query("SELECT id, type, name, description FROM products WHERE type = 'camisas'")
	if err != nil {
		http.Error(w, "Erro ao buscar produtos", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var products []Product
	for rows.Next() {
		var p Product
		if err := rows.Scan(&p.ID, &p.Type, &p.Name, &p.Description); err != nil {
			http.Error(w, "Erro ao ler produtos", http.StatusInternalServerError)
			return
		}
		products = append(products, p)
	}

	data := struct {
		Products []Product
	}{
		Products: products,
	}

	tmpl.Execute(w, data)
}

func canecasHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/canecas.html")
	if err != nil {
		http.Error(w, "Erro ao carregar a página de canecas", http.StatusInternalServerError)
		return
	}

	rows, err := db.Query("SELECT id, type, name, description FROM products WHERE type = 'canecas'")
	if err != nil {
		http.Error(w, "Erro ao buscar produtos", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var products []Product
	for rows.Next() {
		var p Product
		if err := rows.Scan(&p.ID, &p.Type, &p.Name, &p.Description); err != nil {
			http.Error(w, "Erro ao ler produtos", http.StatusInternalServerError)
			return
		}
		products = append(products, p)
	}

	data := struct {
		Products []Product
	}{
		Products: products,
	}

	tmpl.Execute(w, data)
}

func whatsappHandler(w http.ResponseWriter, r *http.Request) {
	var whatsappNumber string
	err := db.QueryRow("SELECT value FROM settings WHERE key = ?", "whatsapp_number").Scan(&whatsappNumber)
	if err == sql.ErrNoRows {
		http.Error(w, "Número do WhatsApp não configurado", http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, "Erro ao buscar número do WhatsApp", http.StatusInternalServerError)
		return
	}

	// Redirecionar para o WhatsApp
	redirectURL := fmt.Sprintf("https://wa.me/%s", whatsappNumber)
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
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