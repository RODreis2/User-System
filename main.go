package main

import (
	"fmt"
	"log"
	"net/http"
	"web-app/handlers"
)

func main() {
	// Initialize database
	err := handlers.InitDB("./webapp.db")
	if err != nil {
		log.Fatal("Failed to initialize database:", err)
	}
	
	// Main routes
	http.HandleFunc("/", handlers.HomeHandler)
	http.HandleFunc("/canecas", handlers.CanecasHandler)
	http.HandleFunc("/camisas", handlers.CamisasHandler)

	// Auth routes
	http.HandleFunc("/login", handlers.AuthLoginHandler)
	http.HandleFunc("/register", handlers.AuthRegisterHandler)

	// User routes
	http.HandleFunc("/profile", handlers.UserProfileHandler)
	http.HandleFunc("/profile/update", handlers.UserUpdateProfileHandler)
	http.HandleFunc("/profile/change-password", handlers.UserChangePasswordHandler)

	// Admin routes
	http.HandleFunc("/admin", handlers.AdminDashboardHandler)
	http.HandleFunc("/admin/users", handlers.AdminUsersManagementHandler)

	// Order routes
	http.HandleFunc("/orders", handlers.OrderListHandler)
	http.HandleFunc("/orders/create", handlers.OrderCreateHandler)
	http.HandleFunc("/orders/view", handlers.OrderGetHandler)

	fmt.Printf("Starting server at port 8080\n")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}