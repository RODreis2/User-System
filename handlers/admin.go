package handlers

import (
	"net/http"
)

// AdminDashboardHandler handles the admin dashboard
func AdminDashboardHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement admin dashboard
	w.Write([]byte("Admin Dashboard - Coming Soon"))
}

// AdminUsersManagementHandler handles user management for admins
func AdminUsersManagementHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement user management
	w.Write([]byte("User Management - Coming Soon"))
}
