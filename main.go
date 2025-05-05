package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

type Product struct {
	ID          int
	Type        string
	Name        string
	Description string
	Price       float64
	Images      []string
}

type CartItem struct {
	ID          int
	Name        string
	Price       float64
	Images      []string
}

func main() {
	// Conexão com o banco de dados SQLite
	var err error
	db, err = sql.Open("sqlite3", "./database.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	// Criação da tabela de usuários, se não existir
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
		description TEXT,
		price REAL NOT NULL
	);`
	_, err = db.Exec(createProductsTable)
	if err != nil {
		panic(err)
	}

	// Criação da tabela de imagens de produtos, se não existir
	createProductImagesTable := `
	CREATE TABLE IF NOT EXISTS product_images (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		product_id INTEGER NOT NULL,
		image_path TEXT NOT NULL,
		FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
	);`
	_, err = db.Exec(createProductImagesTable)
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

	// Criação da tabela de carrinho de compras, se não existir
	createCartTable := `
	CREATE TABLE IF NOT EXISTS cart (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		product_id INTEGER NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
		FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
	);`
	_, err = db.Exec(createCartTable)
	if err != nil {
		panic(err)
	}

	// Criação da tabela de sessões, se não existir
	createSessionsTable := `
	CREATE TABLE IF NOT EXISTS sessions (
		uuid TEXT PRIMARY KEY,
		user_id INTEGER,
		is_admin BOOLEAN DEFAULT FALSE,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);`
	_, err = db.Exec(createSessionsTable)
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

	// Criar diretório para uploads de imagens, se não existir
	uploadDir := "./static/uploads"
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		panic(err)
	}

	// Configuração do servidor de arquivos estáticos
	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	// Rotas
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/admin", adminHandler)
	http.HandleFunc("/admin/dashboard", adminDashboardHandler)
	http.HandleFunc("/admin/add_product", adminAddProductHandler)
	http.HandleFunc("/admin/edit_product", adminEditProductHandler)
	http.HandleFunc("/admin/update_whatsapp", adminUpdateWhatsAppHandler)
	http.HandleFunc("/admin/delete_product/", adminDeleteProductHandler)
	http.HandleFunc("/admin/logout", adminLogoutHandler)
	http.HandleFunc("/produtos", produtosHandler)
	http.HandleFunc("/registrar", registrarHandler)
	http.HandleFunc("/whatsapp", whatsappHandler)
	http.HandleFunc("/carrinho", carrinhoHandler)
	http.HandleFunc("/carrinho/add/", carrinhoAddHandler)
	http.HandleFunc("/carrinho/remove/", carrinhoRemoveHandler)
	http.HandleFunc("/carrinho/checkout", carrinhoCheckoutHandler)
	http.HandleFunc("/logout", logoutHandler)

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
		// Verificar se já está logado
		sessionCookie, err := r.Cookie("session_uuid")
		if err == nil && sessionCookie.Value != "" {
			var userID int
			err = db.QueryRow("SELECT user_id FROM sessions WHERE uuid = ?", sessionCookie.Value).Scan(&userID)
			if err == nil {
				http.Redirect(w, r, "/produtos", http.StatusSeeOther)
				return
			}
		}

		tmpl, err := template.ParseFiles("templates/login.html")
		if err != nil {
			http.Error(w, "Erro ao carregar a página de login", http.StatusInternalServerError)
			return
		}
		data := struct {
			CartCount int
		}{
			CartCount: 0,
		}
		tmpl.Execute(w, data)
		return
	}

	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")

		// Buscar usuário no banco de dados
		var storedPassword string
		var userID int
		err := db.QueryRow("SELECT id, password FROM users WHERE username = ?", username).Scan(&userID, &storedPassword)
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

		// Criar UUID para sessão
		sessionUUID := uuid.New().String()

		// Salvar sessão no banco de dados
		_, err = db.Exec("INSERT INTO sessions (uuid, user_id, is_admin) VALUES (?, ?, ?)", sessionUUID, userID, false)
		if err != nil {
			http.Error(w, "Erro ao criar sessão", http.StatusInternalServerError)
			return
		}

		// Definir cookie de sessão com UUID
		cookie := http.Cookie{
			Name:  "session_uuid",
			Value: sessionUUID,
			Path:  "/",
			MaxAge: 86400, // 24 horas
		}
		http.SetCookie(w, &cookie)

		// Redirecionar para a página inicial com mensagem de sucesso
		http.Redirect(w, r, "/?message=Login+realizado+com+sucesso", http.StatusSeeOther)
		return
	}
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		// Verificar se já está logado como admin
		sessionCookie, err := r.Cookie("session_uuid")
		if err == nil && sessionCookie.Value != "" {
			var isAdmin bool
			err = db.QueryRow("SELECT is_admin FROM sessions WHERE uuid = ?", sessionCookie.Value).Scan(&isAdmin)
			if err == nil && isAdmin {
				http.Redirect(w, r, "/admin/dashboard", http.StatusSeeOther)
				return
			}
		}

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
		var adminID int
		err := db.QueryRow("SELECT id, password FROM admins WHERE username = ?", username).Scan(&adminID, &storedPassword)
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

		// Criar UUID para sessão
		sessionUUID := uuid.New().String()

		// Salvar sessão no banco de dados como admin
		_, err = db.Exec("INSERT INTO sessions (uuid, user_id, is_admin) VALUES (?, ?, ?)", sessionUUID, adminID, true)
		if err != nil {
			http.Error(w, "Erro ao criar sessão de admin", http.StatusInternalServerError)
			return
		}

		// Definir cookie de sessão com UUID
		cookie := http.Cookie{
			Name:  "session_uuid",
			Value: sessionUUID,
			Path:  "/",
			MaxAge: 86400, // 24 horas
		}
		http.SetCookie(w, &cookie)

		// Redirecionar para o painel de administração
		http.Redirect(w, r, "/admin/dashboard", http.StatusSeeOther)
		return
	}
}

func adminDashboardHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		// Verificar se está logado como admin
		sessionCookie, err := r.Cookie("session_uuid")
		if err != nil || sessionCookie.Value == "" {
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
			return
		}

		var isAdmin bool
		err = db.QueryRow("SELECT is_admin FROM sessions WHERE uuid = ?", sessionCookie.Value).Scan(&isAdmin)
		if err != nil || !isAdmin {
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
			return
		}

		tmpl, err := template.ParseFiles("templates/admin_dashboard.html")
		if err != nil {
			http.Error(w, "Erro ao carregar o painel de admin", http.StatusInternalServerError)
			return
		}
		rows, err := db.Query("SELECT id, type, name, description, price FROM products")
		if err != nil {
			http.Error(w, "Erro ao buscar produtos", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var products []Product
		for rows.Next() {
			var p Product
			if err := rows.Scan(&p.ID, &p.Type, &p.Name, &p.Description, &p.Price); err != nil {
				http.Error(w, "Erro ao ler produtos", http.StatusInternalServerError)
				return
			}
			// Buscar imagens do produto
			imgRows, err := db.Query("SELECT image_path FROM product_images WHERE product_id = ?", p.ID)
			if err != nil {
				continue
			}
			defer imgRows.Close()
			for imgRows.Next() {
				var imgPath string
				if err := imgRows.Scan(&imgPath); err != nil {
					continue
				}
				p.Images = append(p.Images, imgPath)
			}
			products = append(products, p)
		}

		data := struct {
			Products []Product
		}{
			Products: products,
		}
		tmpl.Execute(w, data)
		return
	}
}

func adminAddProductHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		// Verificar se está logado como admin
		sessionCookie, err := r.Cookie("session_uuid")
		if err != nil || sessionCookie.Value == "" {
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
			return
		}

		var isAdmin bool
		err = db.QueryRow("SELECT is_admin FROM sessions WHERE uuid = ?", sessionCookie.Value).Scan(&isAdmin)
		if err != nil || !isAdmin {
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
			return
		}

		err = r.ParseMultipartForm(10 << 20) // 10MB max memory
		if err != nil {
			http.Error(w, "Erro ao processar formulário", http.StatusInternalServerError)
			return
		}

		productType := r.FormValue("product_type")
		productName := r.FormValue("product_name")
		productDescription := r.FormValue("product_description")
		productPriceStr := r.FormValue("product_price")
		productPrice, err := strconv.ParseFloat(productPriceStr, 64)
		if err != nil {
			http.Error(w, "Preço inválido", http.StatusBadRequest)
			return
		}

		// Inserir produto no banco de dados
		result, err := db.Exec("INSERT INTO products (type, name, description, price) VALUES (?, ?, ?, ?)", productType, productName, productDescription, productPrice)
		if err != nil {
			http.Error(w, "Erro ao adicionar produto", http.StatusInternalServerError)
			return
		}

		productID, _ := result.LastInsertId()

		// Processar upload de imagens
		files := r.MultipartForm.File["product_images"]
		for i, file := range files {
			if i >= 5 { // Limitar a 5 imagens
				break
			}
			src, err := file.Open()
			if err != nil {
				continue
			}
			defer src.Close()

			// Criar caminho único para a imagem
			ext := filepath.Ext(file.Filename)
			newFilename := fmt.Sprintf("%d_%d%s", productID, i, ext)
			dstPath := filepath.Join("./static/uploads", newFilename)
			dst, err := os.Create(dstPath)
			if err != nil {
				continue
			}
			defer dst.Close()

			if _, err := io.Copy(dst, src); err != nil {
				continue
			}

			// Salvar caminho da imagem no banco de dados
			_, err = db.Exec("INSERT INTO product_images (product_id, image_path) VALUES (?, ?)", productID, "/static/uploads/"+newFilename)
			if err != nil {
				continue
			}
		}

		http.Redirect(w, r, "/admin/dashboard?message=Produto+adicionado+com+sucesso", http.StatusSeeOther)
		return
	}
	http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
}

func adminEditProductHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		// Verificar se está logado como admin
		sessionCookie, err := r.Cookie("session_uuid")
		if err != nil || sessionCookie.Value == "" {
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
			return
		}

		var isAdmin bool
		err = db.QueryRow("SELECT is_admin FROM sessions WHERE uuid = ?", sessionCookie.Value).Scan(&isAdmin)
		if err != nil || !isAdmin {
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
			return
		}

		err = r.ParseMultipartForm(10 << 20) // 10MB max memory
		if err != nil {
			http.Error(w, "Erro ao processar formulário", http.StatusInternalServerError)
			return
		}

		productIDStr := r.FormValue("product_id")
		productID, err := strconv.Atoi(productIDStr)
		if err != nil {
			http.Error(w, "ID do produto inválido", http.StatusBadRequest)
			return
		}

		productType := r.FormValue("product_type")
		productName := r.FormValue("product_name")
		productDescription := r.FormValue("product_description")
		productPriceStr := r.FormValue("product_price")
		productPrice, err := strconv.ParseFloat(productPriceStr, 64)
		if err != nil {
			http.Error(w, "Preço inválido", http.StatusBadRequest)
			return
		}

		// Atualizar produto no banco de dados
		_, err = db.Exec("UPDATE products SET type = ?, name = ?, description = ?, price = ? WHERE id = ?", productType, productName, productDescription, productPrice, productID)
		if err != nil {
			http.Error(w, "Erro ao atualizar produto", http.StatusInternalServerError)
			return
		}

		// Processar upload de novas imagens, se houver
		files := r.MultipartForm.File["product_images"]
		if len(files) > 0 {
			// Remover imagens antigas
			rows, err := db.Query("SELECT image_path FROM product_images WHERE product_id = ?", productID)
			if err == nil {
				defer rows.Close()
				for rows.Next() {
					var imgPath string
					if err := rows.Scan(&imgPath); err == nil {
						os.Remove("." + imgPath)
					}
				}
			}
			_, err = db.Exec("DELETE FROM product_images WHERE product_id = ?", productID)
			if err != nil {
				http.Error(w, "Erro ao remover imagens antigas", http.StatusInternalServerError)
				return
			}

			// Adicionar novas imagens
			for i, file := range files {
				if i >= 5 { // Limitar a 5 imagens
					break
				}
				src, err := file.Open()
				if err != nil {
					continue
				}
				defer src.Close()

				ext := filepath.Ext(file.Filename)
				newFilename := fmt.Sprintf("%d_%d%s", productID, i, ext)
				dstPath := filepath.Join("./static/uploads", newFilename)
				dst, err := os.Create(dstPath)
				if err != nil {
					continue
				}
				defer dst.Close()

				if _, err := io.Copy(dst, src); err != nil {
					continue
				}

				_, err = db.Exec("INSERT INTO product_images (product_id, image_path) VALUES (?, ?)", productID, "/static/uploads/"+newFilename)
				if err != nil {
					continue
				}
			}
		}

		http.Redirect(w, r, "/admin/dashboard?message=Produto+atualizado+com+sucesso", http.StatusSeeOther)
		return
	}
	http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
}

func adminDeleteProductHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "DELETE" {
		// Verificar se está logado como admin
		sessionCookie, err := r.Cookie("session_uuid")
		if err != nil || sessionCookie.Value == "" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success": false, "message": "Não autorizado"}`))
			return
		}

		var isAdmin bool
		err = db.QueryRow("SELECT is_admin FROM sessions WHERE uuid = ?", sessionCookie.Value).Scan(&isAdmin)
		if err != nil || !isAdmin {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success": false, "message": "Não autorizado"}`))
			return
		}

		pathParts := strings.Split(r.URL.Path, "/")
		if len(pathParts) < 4 {
			http.Error(w, "ID do produto não fornecido", http.StatusBadRequest)
			return
		}
		productIDStr := pathParts[len(pathParts)-1]
		productID, err := strconv.Atoi(productIDStr)
		if err != nil {
			http.Error(w, "ID do produto inválido", http.StatusBadRequest)
			return
		}

		// Excluir imagens associadas
		rows, err := db.Query("SELECT image_path FROM product_images WHERE product_id = ?", productID)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var imgPath string
				if err := rows.Scan(&imgPath); err == nil {
					os.Remove("." + imgPath) // Remove arquivo do sistema
				}
			}
		}

		// Excluir produto (e imagens via ON DELETE CASCADE)
		_, err = db.Exec("DELETE FROM products WHERE id = ?", productID)
		if err != nil {
			http.Error(w, "Erro ao excluir produto", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success": true}`))
		return
	}
	http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
}

func adminLogoutHandler(w http.ResponseWriter, r *http.Request) {
	// Limpar cookie de sessão
	sessionCookie, err := r.Cookie("session_uuid")
	if err == nil && sessionCookie.Value != "" {
		_, err = db.Exec("DELETE FROM sessions WHERE uuid = ?", sessionCookie.Value)
		if err != nil {
			http.Error(w, "Erro ao encerrar sessão", http.StatusInternalServerError)
			return
		}
	}

	cookie := http.Cookie{
		Name:   "session_uuid",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	}
	http.SetCookie(w, &cookie)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// Limpar cookie de sessão
	sessionCookie, err := r.Cookie("session_uuid")
	if err == nil && sessionCookie.Value != "" {
		_, err = db.Exec("DELETE FROM sessions WHERE uuid = ?", sessionCookie.Value)
		if err != nil {
			http.Error(w, "Erro ao encerrar sessão", http.StatusInternalServerError)
			return
		}
	}

	cookie := http.Cookie{
		Name:   "session_uuid",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	}
	http.SetCookie(w, &cookie)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func adminUpdateWhatsAppHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		// Verificar se está logado como admin
		sessionCookie, err := r.Cookie("session_uuid")
		if err != nil || sessionCookie.Value == "" {
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
			return
		}

		var isAdmin bool
		err = db.QueryRow("SELECT is_admin FROM sessions WHERE uuid = ?", sessionCookie.Value).Scan(&isAdmin)
		if err != nil || !isAdmin {
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
			return
		}

		whatsappNumber := r.FormValue("whatsapp_number")

		// Atualizar número do WhatsApp no banco de dados
		_, err = db.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", "whatsapp_number", whatsappNumber)
		if err != nil {
			http.Error(w, "Erro ao atualizar número do WhatsApp", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/admin/dashboard?message=Número+do+WhatsApp+atualizado+com+sucesso", http.StatusSeeOther)
		return
	}
	http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
}

func produtosHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/produtos.html")
	if err != nil {
		http.Error(w, "Erro ao carregar a página de produtos", http.StatusInternalServerError)
		return
	}

	rows, err := db.Query("SELECT id, type, name, description, price FROM products")
	if err != nil {
		http.Error(w, "Erro ao buscar produtos", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var products []Product
	for rows.Next() {
		var p Product
		if err := rows.Scan(&p.ID, &p.Type, &p.Name, &p.Description, &p.Price); err != nil {
			http.Error(w, "Erro ao ler produtos", http.StatusInternalServerError)
			return
		}
		// Buscar imagens do produto
		imgRows, err := db.Query("SELECT image_path FROM product_images WHERE product_id = ?", p.ID)
		if err != nil {
			continue
		}
		defer imgRows.Close()
		for imgRows.Next() {
			var imgPath string
			if err := imgRows.Scan(&imgPath); err != nil {
				continue
			}
			p.Images = append(p.Images, imgPath)
		}
		products = append(products, p)
	}

	// Contar itens no carrinho do usuário
	cartCount := 0
	isLoggedIn := false
	sessionCookie, err := r.Cookie("session_uuid")
	if err == nil && sessionCookie.Value != "" {
		var userID int
		err = db.QueryRow("SELECT user_id FROM sessions WHERE uuid = ?", sessionCookie.Value).Scan(&userID)
		if err == nil {
			isLoggedIn = true
			err = db.QueryRow("SELECT COUNT(*) FROM cart WHERE user_id = ?", userID).Scan(&cartCount)
			if err != nil {
				cartCount = 0
			}
		}
	}

	data := struct {
		Products   []Product
		CartCount  int
		IsLoggedIn bool
	}{
		Products:   products,
		CartCount:  cartCount,
		IsLoggedIn: isLoggedIn,
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
		// Verificar se já está logado
		sessionCookie, err := r.Cookie("session_uuid")
		if err == nil && sessionCookie.Value != "" {
			var userID int
			err = db.QueryRow("SELECT user_id FROM sessions WHERE uuid = ?", sessionCookie.Value).Scan(&userID)
			if err == nil {
				http.Redirect(w, r, "/produtos", http.StatusSeeOther)
				return
			}
		}

		tmpl, err := template.ParseFiles("templates/registrar.html")
		if err != nil {
			http.Error(w, "Erro ao carregar a página de registro", http.StatusInternalServerError)
			return
		}
		data := struct {
			CartCount int
		}{
			CartCount: 0,
		}
		tmpl.Execute(w, data)
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

		// Inserir no banco de dados
		result, err := db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", username, hashedPassword)
		if err != nil {
			http.Error(w, "Erro ao registrar: usuário já existe", http.StatusBadRequest)
			return
		}

		// Criar UUID para sessão
		userID, _ := result.LastInsertId()
		sessionUUID := uuid.New().String()

		// Salvar sessão no banco de dados
		_, err = db.Exec("INSERT INTO sessions (uuid, user_id, is_admin) VALUES (?, ?, ?)", sessionUUID, userID, false)
		if err != nil {
			http.Error(w, "Erro ao criar sessão", http.StatusInternalServerError)
			return
		}

		// Definir cookie de sessão com UUID
		cookie := http.Cookie{
			Name:  "session_uuid",
			Value: sessionUUID,
			Path:  "/",
			MaxAge: 86400, // 24 horas
		}
		http.SetCookie(w, &cookie)

		// Redirecionar para a página inicial com mensagem de sucesso
		http.Redirect(w, r, "/?message=Registro+realizado+com+sucesso", http.StatusSeeOther)
		return
	}
}

func carrinhoHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		// Verificar se está logado como usuário
		sessionCookie, err := r.Cookie("session_uuid")
		if err != nil || sessionCookie.Value == "" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		var userID int
		err = db.QueryRow("SELECT user_id FROM sessions WHERE uuid = ?", sessionCookie.Value).Scan(&userID)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		tmpl, err := template.ParseFiles("templates/carrinho.html")
		if err != nil {
			http.Error(w, "Erro ao carregar a página do carrinho", http.StatusInternalServerError)
			return
		}

		rows, err := db.Query(`
			SELECT p.id, p.name, p.price
			FROM cart c
			JOIN products p ON c.product_id = p.id
			WHERE c.user_id = ?`, userID)
		if err != nil {
			http.Error(w, "Erro ao buscar itens do carrinho", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var cartItems []CartItem
		total := 0.0
		for rows.Next() {
			var item CartItem
			if err := rows.Scan(&item.ID, &item.Name, &item.Price); err != nil {
				http.Error(w, "Erro ao ler itens do carrinho", http.StatusInternalServerError)
				return
			}
			// Buscar imagens do produto
			imgRows, err := db.Query("SELECT image_path FROM product_images WHERE product_id = ?", item.ID)
			if err != nil {
				continue
			}
			defer imgRows.Close()
			for imgRows.Next() {
				var imgPath string
				if err := imgRows.Scan(&imgPath); err != nil {
					continue
				}
				item.Images = append(item.Images, imgPath)
			}
			cartItems = append(cartItems, item)
			total += item.Price
		}

		// Contar itens no carrinho
		var cartCount int
		err = db.QueryRow("SELECT COUNT(*) FROM cart WHERE user_id = ?", userID).Scan(&cartCount)
		if err != nil {
			cartCount = 0
		}

		data := struct {
			CartItems  []CartItem
			Total      float64
			CartCount  int
			IsLoggedIn bool
		}{
			CartItems:  cartItems,
			Total:      total,
			CartCount:  cartCount,
			IsLoggedIn: true,
		}

		tmpl.Execute(w, data)
		return
	}
	http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
}

func carrinhoAddHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		// Verificar se está logado como usuário
		sessionCookie, err := r.Cookie("session_uuid")
		if err != nil || sessionCookie.Value == "" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success": false, "message": "Faça login primeiro"}`))
			return
		}

		var userID int
		err = db.QueryRow("SELECT user_id FROM sessions WHERE uuid = ?", sessionCookie.Value).Scan(&userID)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success": false, "message": "Faça login primeiro"}`))
			return
		}

		pathParts := strings.Split(r.URL.Path, "/")
		if len(pathParts) < 4 {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success": false, "message": "ID do produto não fornecido"}`))
			return
		}

		productIDStr := pathParts[len(pathParts)-1]
		productID, err := strconv.Atoi(productIDStr)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success": false, "message": "ID do produto inválido"}`))
			return
		}

		// Adicionar ao carrinho
		_, err = db.Exec("INSERT INTO cart (user_id, product_id) VALUES (?, ?)", userID, productID)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success": false, "message": "Erro ao adicionar ao carrinho"}`))
			return
		}

		// Contar itens no carrinho
		var cartCount int
		err = db.QueryRow("SELECT COUNT(*) FROM cart WHERE user_id = ?", userID).Scan(&cartCount)
		if err != nil {
			cartCount = 0
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(fmt.Sprintf(`{"success": true, "cartCount": %d}`, cartCount)))
		return
	}
	http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
}

func carrinhoRemoveHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "DELETE" {
		// Verificar se está logado como usuário
		sessionCookie, err := r.Cookie("session_uuid")
		if err != nil || sessionCookie.Value == "" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success": false, "message": "Faça login primeiro"}`))
			return
		}

		var userID int
		err = db.QueryRow("SELECT user_id FROM sessions WHERE uuid = ?", sessionCookie.Value).Scan(&userID)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success": false, "message": "Faça login primeiro"}`))
			return
		}

		pathParts := strings.Split(r.URL.Path, "/")
		if len(pathParts) < 4 {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success": false, "message": "ID do produto não fornecido"}`))
			return
		}

		productIDStr := pathParts[len(pathParts)-1]
		productID, err := strconv.Atoi(productIDStr)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success": false, "message": "ID do produto inválido"}`))
			return
		}

		// Remover do carrinho
		_, err = db.Exec("DELETE FROM cart WHERE user_id = ? AND product_id = ?", userID, productID)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success": false, "message": "Erro ao remover do carrinho"}`))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success": true}`))
		return
	}
	http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
}

func carrinhoCheckoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		// Verificar se está logado como usuário
		sessionCookie, err := r.Cookie("session_uuid")
		if err != nil || sessionCookie.Value == "" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success": false, "message": "Faça login primeiro"}`))
			return
		}

		var userID int
		err = db.QueryRow("SELECT user_id FROM sessions WHERE uuid = ?", sessionCookie.Value).Scan(&userID)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success": false, "message": "Faça login primeiro"}`))
			return
		}

		// Buscar número do WhatsApp
		var whatsappNumber string
		err = db.QueryRow("SELECT value FROM settings WHERE key = ?", "whatsapp_number").Scan(&whatsappNumber)
		if err == sql.ErrNoRows {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success": false, "message": "Número do WhatsApp não configurado"}`))
			return
		}
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success": false, "message": "Erro ao buscar número do WhatsApp"}`))
			return
		}

		// Buscar itens do carrinho
		rows, err := db.Query(`
			SELECT p.id, p.name, p.price
			FROM cart c
			JOIN products p ON c.product_id = p.id
			WHERE c.user_id = ?`, userID)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success": false, "message": "Erro ao buscar itens do carrinho"}`))
			return
		}
		defer rows.Close()

		var cartItems []CartItem
		total := 0.0
		message := "Olá, gostaria de comprar os seguintes itens:\n"
		for rows.Next() {
			var item CartItem
			if err := rows.Scan(&item.ID, &item.Name, &item.Price); err != nil {
				continue
			}
			cartItems = append(cartItems, item)
			total += item.Price
			message += fmt.Sprintf("- %s (R$ %.2f)\n", item.Name, item.Price)
		}
		message += fmt.Sprintf("\nTotal: R$ %.2f", total)

		// Limpar carrinho após checkout
		_, err = db.Exec("DELETE FROM cart WHERE user_id = ?", userID)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success": false, "message": "Erro ao limpar carrinho"}`))
			return
		}

		// Criar URL de redirecionamento para WhatsApp com a mensagem
		redirectURL := fmt.Sprintf("https://wa.me/%s?text=%s", whatsappNumber, urlEncode(message))

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(fmt.Sprintf(`{"success": true, "redirectUrl": "%s"}`, redirectURL)))
		return
	}
	http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
}

func urlEncode(text string) string {
	return strings.ReplaceAll(strings.ReplaceAll(text, " ", "%20"), "\n", "%0A")
}