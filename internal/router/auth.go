package router

import (
	"errors"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/crypto/bcrypt"
)

var usernamePattern = regexp.MustCompile(`^[a-z0-9_]{3,32}$`)

// requireAuth rejects unauthenticated requests and exposes the user ID to the
// protected handler through the request context.
func (s *server) requireAuth(c *gin.Context) {
	userID, ok := s.currentUserID(c)
	if !ok {
		c.Redirect(http.StatusSeeOther, "/login")
		c.Abort()
		return
	}
	c.Set(contextUserID, userID)
	c.Next()
}

// currentUserID validates the signed session cookie and returns the user ID.
func (s *server) currentUserID(c *gin.Context) (int64, bool) {
	value, err := c.Cookie(sessionCookie)
	if err != nil || value == "" {
		return 0, false
	}
	userID, err := s.sessions.UserID(value, time.Now())
	if err != nil {
		return 0, false
	}
	return userID, true
}

// redirectIfAuthenticated sends already-signed-in users to their dashboard so
// the landing, login, and signup pages are never shown while logged in.
func (s *server) redirectIfAuthenticated(c *gin.Context) {
	if _, ok := s.currentUserID(c); ok {
		c.Redirect(http.StatusSeeOther, "/dashboard")
		c.Abort()
		return
	}
	c.Next()
}

func (s *server) login(c *gin.Context) {
	email := strings.ToLower(strings.TrimSpace(c.PostForm("email")))
	password := c.PostForm("password")

	var id int64
	var passwordHash string
	err := s.conn.QueryRowContext(c.Request.Context(), "SELECT id, password_hash FROM users WHERE email = $1", email).Scan(&id, &passwordHash)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)) != nil {
		redirectWithError(c, "/login", "Incorrect email or password.")
		return
	}

	s.setSession(c, id)
	c.Redirect(http.StatusSeeOther, "/dashboard")
}

func (s *server) signup(c *gin.Context) {
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
	err = s.conn.QueryRowContext(c.Request.Context(), `
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

	s.setSession(c, id)
	c.Redirect(http.StatusSeeOther, "/dashboard")
}

func (s *server) logout(c *gin.Context) {
	c.SetCookie(sessionCookie, "", -1, "/", "", secureCookies(), true)
	c.Redirect(http.StatusSeeOther, "/")
}

func (s *server) setSession(c *gin.Context, userID int64) {
	c.SetCookie(sessionCookie, s.sessions.Create(userID, time.Now()), int(s.sessions.Duration().Seconds()), "/", "", secureCookies(), true)
}

func redirectWithError(c *gin.Context, path, message string) {
	c.Redirect(http.StatusSeeOther, path+"?error="+url.QueryEscape(message))
}

func secureCookies() bool {
	return os.Getenv("GIN_MODE") == gin.ReleaseMode
}
