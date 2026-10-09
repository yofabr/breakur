// Package router wires up the Gin engine and all HTTP routes.
package router

import (
	"database/sql"
	"html/template"
	"net/http"
	"os"

	"breakur/internal/auth"

	"github.com/gin-gonic/gin"
)

const (
	indexFile     = "public/index.html"
	loginFile     = "public/login.html"
	signupFile    = "public/signup.html"
	dashboardFile = "public/dashboard.html"
)

const (
	sessionCookie = "breakur_session"
	contextUserID = "userID"
)

// server holds the dependencies every handler needs.
type server struct {
	conn      *sql.DB
	sessions  *auth.SessionManager
	dashboard *template.Template
}

// New builds the Gin engine with all routes registered.
func New(conn *sql.DB) *gin.Engine {
	sessions, err := auth.NewSessionManager(os.Getenv("AUTH_SESSION_SECRET"))
	if err != nil {
		panic("create session manager: " + err.Error())
	}

	dashboard, err := template.ParseFiles(dashboardFile)
	if err != nil {
		panic("parse dashboard template: " + err.Error())
	}

	s := &server{conn: conn, sessions: sessions, dashboard: dashboard}

	r := gin.Default()

	// Static pages.
	r.GET("/", func(c *gin.Context) { c.File(indexFile) })
	r.GET("/login", func(c *gin.Context) { c.File(loginFile) })
	r.POST("/login", s.login)
	r.GET("/signup", func(c *gin.Context) { c.File(signupFile) })
	r.POST("/signup", s.signup)
	r.POST("/logout", s.logout)

	// Authenticated dashboard and link management.
	r.GET("/dashboard", s.requireAuth, s.showDashboard)
	r.POST("/links", s.requireAuth, s.createLink)
	r.POST("/links/:id/delete", s.requireAuth, s.deleteLink)

	// Serve the rest of public/ (css, js, images, ...) alongside it.
	r.StaticFS("/public", http.Dir("public"))

	// Short-link redirects are registered last so the explicit routes above
	// always win for reserved names such as "login" or "dashboard".
	r.GET("/:shortCode", s.redirectLink)

	return r
}
