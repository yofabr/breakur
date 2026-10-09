// Package router wires up the Gin engine and all HTTP routes.
package router

import (
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"breakur/internal/auth"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/crypto/bcrypt"
)

const (
	indexFile  = "public/index.html"
	loginFile  = "public/login.html"
	signupFile = "public/signup.html"
)

const sessionCookie = "breakur_session"

var usernamePattern = regexp.MustCompile(`^[a-z0-9_]{3,32}$`)

// New builds the Gin engine with all routes registered.
func New(conn *sql.DB) *gin.Engine {
	r := gin.Default()
	sessions, err := auth.NewSessionManager(os.Getenv("AUTH_SESSION_SECRET"))
	if err != nil {
		panic("create session manager: " + err.Error())
	}

	// Static pages.
	r.GET("/", func(c *gin.Context) {
		c.File(indexFile)
	})

	r.GET("/login", func(c *gin.Context) {
		c.File(loginFile)
	})
	r.POST("/login", func(c *gin.Context) {
		email := strings.ToLower(strings.TrimSpace(c.PostForm("email")))
		password := c.PostForm("password")

		var id int64
		var passwordHash string
		err := conn.QueryRowContext(c.Request.Context(), "SELECT id, password_hash FROM users WHERE email = $1", email).Scan(&id, &passwordHash)
		if err != nil || bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)) != nil {
			redirectWithError(c, "/login", "Incorrect email or password.")
			return
		}

		setSession(c, sessions, id)
		c.Redirect(http.StatusSeeOther, "/")
	})

	r.GET("/signup", func(c *gin.Context) {
		c.File(signupFile)
	})
	r.POST("/signup", func(c *gin.Context) {
		name := strings.TrimSpace(c.PostForm("name"))
		username := strings.ToLower(strings.TrimSpace(c.PostForm("username")))
		email := strings.ToLower(strings.TrimSpace(c.PostForm("email")))
		password := c.PostForm("password")

		if name == "" || len(name) > 120 || !usernamePattern.MatchString(username) || len(password) < 8 {
			redirectWithError(c, "/signup", "Use a name, a 3–32 character username, and an 8+ character password.")
			return
		}

		passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			redirectWithError(c, "/signup", "Could not create your account. Please try again.")
			return
		}

		var id int64
		err = conn.QueryRowContext(c.Request.Context(), `
			INSERT INTO users (name, username, email, password_hash)
			VALUES ($1, $2, $3, $4)
			RETURNING id`, name, username, email, string(passwordHash)).Scan(&id)
		if err != nil {
			var pgErr *pgconn.PgError
			if strings.Contains(err.Error(), "users_email_key") || strings.Contains(err.Error(), "users_username_key") || (errors.As(err, &pgErr) && pgErr.Code == "23505") {
				redirectWithError(c, "/signup", "That email or username is already in use.")
				return
			}
			redirectWithError(c, "/signup", "Could not create your account. Please try again.")
			return
		}

		setSession(c, sessions, id)
		c.Redirect(http.StatusSeeOther, "/")
	})

	r.POST("/logout", func(c *gin.Context) {
		c.SetCookie(sessionCookie, "", -1, "/", "", secureCookies(), true)
		c.Redirect(http.StatusSeeOther, "/")
	})

	// Serve the rest of public/ (css, js, images, ...) alongside it.
	r.StaticFS("/public", http.Dir("public"))

	return r
}

func redirectWithError(c *gin.Context, path, message string) {
	c.Redirect(http.StatusSeeOther, path+"?error="+url.QueryEscape(message))
}

func setSession(c *gin.Context, sessions *auth.SessionManager, userID int64) {
	c.SetCookie(sessionCookie, sessions.Create(userID, time.Now()), int(auth.SessionDuration.Seconds()), "/", "", secureCookies(), true)
}

func secureCookies() bool {
	return os.Getenv("GIN_MODE") == gin.ReleaseMode
}
