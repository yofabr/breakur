package router

import (
	"context"
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"breakur/internal/auth"
	"breakur/internal/db"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

const testSecret = "test-session-secret"

var testCounter atomic.Int64

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	// The server resolves public/ relative to the working directory, so run
	// tests from the module root.
	if err := os.Chdir("../.."); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

// ---------------------------------------------------------------------------
// Pure validation and generation helpers
// ---------------------------------------------------------------------------

func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		name   string
		in     string
		want   string
		wantOK bool
	}{
		{"https with path", "https://example.com/path", "https://example.com/path", true},
		{"trims spaces", "  https://example.com  ", "https://example.com", true},
		{"http", "http://example.com", "http://example.com", true},
		{"upper scheme", "HTTP://Example.com/Path", "http://Example.com/Path", true},
		{"query", "https://example.com/a?b=1&c=2", "https://example.com/a?b=1&c=2", true},
		{"ftp rejected", "ftp://example.com", "", false},
		{"javascript rejected", "javascript:alert(1)", "", false},
		{"missing scheme", "example.com", "", false},
		{"empty", "", "", false},
		{"missing host", "https://", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := normalizeURL(tt.in)
			if ok != tt.wantOK {
				t.Fatalf("normalizeURL(%q) ok = %v, want %v", tt.in, ok, tt.wantOK)
			}
			if got != tt.want {
				t.Fatalf("normalizeURL(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestValidCustomCode(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"empty generates", "", "", false},
		{"simple", "abc123", "abc123", false},
		{"hyphen underscore", "my-link_1", "my-link_1", false},
		{"trimmed", "  pad  ", "pad", false},
		{"max length", strings.Repeat("a", 64), strings.Repeat("a", 64), false},
		{"too long", strings.Repeat("a", 65), "", true},
		{"space invalid", "bad code", "", true},
		{"slash invalid", "bad/code", "", true},
		{"reserved lowercase", "dashboard", "", true},
		{"reserved mixed case", "DashBoard", "", true},
		{"reserved static prefix", "public", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validCustomCode(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validCustomCode(%q) err = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("validCustomCode(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestGenerateShortCode(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 2000; i++ {
		code, err := generateShortCode(shortCodeLength)
		if err != nil {
			t.Fatalf("generateShortCode: %v", err)
		}
		if len(code) != shortCodeLength {
			t.Fatalf("code %q length = %d, want %d", code, len(code), shortCodeLength)
		}
		if !shortCodePattern.MatchString(code) {
			t.Fatalf("code %q does not match the short code pattern", code)
		}
		seen[code] = true
	}
	if len(seen) < 1900 {
		t.Fatalf("expected mostly unique codes, got %d unique out of 2000", len(seen))
	}
}

// ---------------------------------------------------------------------------
// Route protection (no database access)
// ---------------------------------------------------------------------------

func TestProtectedRoutesRedirectToLogin(t *testing.T) {
	r := New(lazyDB(t))

	tests := []struct {
		name string
		req  func() *http.Request
	}{
		{"dashboard", func() *http.Request { return httptest.NewRequest(http.MethodGet, "/dashboard", nil) }},
		{"create link", func() *http.Request { return httptest.NewRequest(http.MethodPost, "/links", nil) }},
		{"delete link", func() *http.Request { return httptest.NewRequest(http.MethodPost, "/links/1/delete", nil) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r.ServeHTTP(w, tt.req())

			if w.Code != http.StatusSeeOther {
				t.Fatalf("status = %d, want %d", w.Code, http.StatusSeeOther)
			}
			if loc := w.Header().Get("Location"); loc != "/login" {
				t.Fatalf("Location = %q, want /login", loc)
			}
		})
	}
}

func TestInvalidSessionCookieIsRejected(t *testing.T) {
	r := New(lazyDB(t))

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: "not.a.real.session"})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" {
		t.Fatalf("got status %d location %q, want 303 /login", w.Code, w.Header().Get("Location"))
	}
}

// ---------------------------------------------------------------------------
// Integration tests (require Postgres; skipped when unavailable)
// ---------------------------------------------------------------------------

func TestLoginFlowRedirectsToDashboard(t *testing.T) {
	conn := requireDB(t)
	withSecret(t)
	r := New(conn)

	email := "login-" + uniqueSuffix() + "@example.com"
	hash, err := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	var id int64
	if err := conn.QueryRowContext(context.Background(),
		`INSERT INTO users (name, username, email, password_hash) VALUES ($1,$2,$3,$4) RETURNING id`,
		"Login User", "u"+uniqueSuffix(), email, string(hash)).Scan(&id); err != nil {
		t.Fatalf("create user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = conn.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, id)
	})

	w := doPost(r, nil, "/login", url.Values{"email": {email}, "password": {"password123"}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/dashboard" {
		t.Fatalf("login: status %d location %q, want 303 /dashboard", w.Code, w.Header().Get("Location"))
	}

	var cookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("login response did not set a session cookie")
	}

	if body := doGetBody(r, cookie, "/dashboard"); !strings.Contains(body, "YOUR LINKS.") {
		t.Fatalf("dashboard did not render for logged-in user")
	}
}

func TestLinkLifecycle(t *testing.T) {
	conn := requireDB(t)
	r, sessions := newTestRouter(t, conn)

	owner := createTestUser(t, conn)
	stranger := createTestUser(t, conn)
	ownerCookie := authCookie(sessions, owner)
	strangerCookie := authCookie(sessions, stranger)

	destination := "https://example.com/a?b=1"
	code := "lifecycle" + uniqueSuffix()

	// Create with a custom code.
	w := doPost(r, ownerCookie, "/links", url.Values{"url": {destination}, "code": {code}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("create: status = %d, want 303", w.Code)
	}
	if loc := w.Header().Get("Location"); !strings.HasPrefix(loc, "/dashboard?notice=") {
		t.Fatalf("create: Location = %q, want notice redirect", loc)
	}

	// Owner sees the link on their dashboard.
	if body := doGetBody(r, ownerCookie, "/dashboard"); !strings.Contains(body, code) || !strings.Contains(body, destination) {
		t.Fatalf("owner dashboard is missing the created link")
	}

	// A different user must not see it.
	if body := doGetBody(r, strangerCookie, "/dashboard"); strings.Contains(body, code) {
		t.Fatalf("stranger dashboard leaked another user's link")
	}

	// Following the short link redirects to the destination.
	rec := doGet(r, nil, "/"+code)
	if rec.Code != http.StatusFound {
		t.Fatalf("redirect: status = %d, want %d", rec.Code, http.StatusFound)
	}
	if loc := rec.Header().Get("Location"); loc != destination {
		t.Fatalf("redirect: Location = %q, want %q", loc, destination)
	}

	// A stranger cannot delete the link.
	id := linkID(t, conn, code)
	if w := doPost(r, strangerCookie, "/links/"+strconv.FormatInt(id, 10)+"/delete", nil); !strings.HasPrefix(w.Header().Get("Location"), "/dashboard?error=") {
		t.Fatalf("stranger delete: expected error redirect, got %q", w.Header().Get("Location"))
	}
	if !linkExists(t, conn, code) {
		t.Fatal("stranger deleted another user's link")
	}

	// The owner can delete the link.
	if w := doPost(r, ownerCookie, "/links/"+strconv.FormatInt(id, 10)+"/delete", nil); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/dashboard" {
		t.Fatalf("owner delete: status %d location %q", w.Code, w.Header().Get("Location"))
	}
	if linkExists(t, conn, code) {
		t.Fatal("owner delete did not remove the link")
	}
}

func TestCreateLinkValidation(t *testing.T) {
	conn := requireDB(t)
	r, sessions := newTestRouter(t, conn)

	user := createTestUser(t, conn)
	cookie := authCookie(sessions, user)

	existing := "taken" + uniqueSuffix()
	if w := doPost(r, cookie, "/links", url.Values{"url": {"https://example.com"}, "code": {existing}}); w.Code != http.StatusSeeOther {
		t.Fatalf("seed link: status = %d", w.Code)
	}

	tests := []struct {
		name    string
		form    url.Values
		message string
	}{
		{"invalid url", url.Values{"url": {"ftp://example.com"}}, "valid"},
		{"empty url", url.Values{"url": {""}}, "valid"},
		{"invalid code", url.Values{"url": {"https://example.com"}, "code": {"bad code"}}, "may only use"},
		{"reserved code", url.Values{"url": {"https://example.com"}, "code": {"dashboard"}}, "reserved"},
		{"duplicate code", url.Values{"url": {"https://example.com"}, "code": {existing}}, "already taken"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := doPost(r, cookie, "/links", tt.form)
			loc := w.Header().Get("Location")
			if !strings.HasPrefix(loc, "/dashboard?error=") {
				t.Fatalf("Location = %q, want error redirect", loc)
			}
			if !strings.Contains(decodeQueryValue(t, loc, "error"), tt.message) {
				t.Fatalf("error %q does not contain %q", decodeQueryValue(t, loc, "error"), tt.message)
			}
		})
	}
}

func TestGeneratedShortCodeIsCreated(t *testing.T) {
	conn := requireDB(t)
	r, sessions := newTestRouter(t, conn)

	user := createTestUser(t, conn)
	cookie := authCookie(sessions, user)
	destination := "https://generated.example/" + uniqueSuffix()

	if w := doPost(r, cookie, "/links", url.Values{"url": {destination}}); w.Code != http.StatusSeeOther {
		t.Fatalf("create generated link: status = %d", w.Code)
	}

	var code string
	if err := conn.QueryRowContext(context.Background(),
		`SELECT short_code FROM links WHERE user_id = $1 AND url = $2`, user, destination).Scan(&code); err != nil {
		t.Fatalf("generated link not found: %v", err)
	}
	if len(code) != shortCodeLength || !shortCodePattern.MatchString(code) {
		t.Fatalf("generated code %q is malformed", code)
	}
}

func TestUnknownShortCodeReturnsNotFound(t *testing.T) {
	conn := requireDB(t)
	withSecret(t)
	r := New(conn)

	rec := doGet(r, nil, "/definitely-not-a-real-code-"+uniqueSuffix())
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	if !strings.Contains(rec.Body.String(), "404") {
		t.Fatalf("404 body did not mention 404")
	}
}

func TestReservedRouteNamesStillServeTheirPages(t *testing.T) {
	conn := requireDB(t)
	withSecret(t)
	r := New(conn)

	// Reserved names must resolve to their real routes, not the short-code
	// catch-all.
	for _, path := range []string{"/login", "/signup", "/"} {
		rec := doGet(r, nil, path)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s status = %d, want 200", path, rec.Code)
		}
	}
}

// ---------------------------------------------------------------------------
// Test infrastructure
// ---------------------------------------------------------------------------

// withSecret sets a fixed session secret for the duration of the test so the
// router and the test helpers sign identical cookies.
func withSecret(t *testing.T) string {
	t.Helper()
	t.Setenv("AUTH_SESSION_SECRET", testSecret)
	return testSecret
}

func newTestRouter(t *testing.T, conn *sql.DB) (*gin.Engine, *auth.SessionManager) {
	t.Helper()
	withSecret(t)
	sessions, err := auth.NewSessionManager(testSecret)
	if err != nil {
		t.Fatalf("new session manager: %v", err)
	}
	return New(conn), sessions
}

// lazyDB returns a handle that never connects; it is enough for tests that only
// exercise routing and middleware before any query runs.
func lazyDB(t *testing.T) *sql.DB {
	t.Helper()
	conn, err := sql.Open("pgx", "postgres://nobody:nobody@127.0.0.1:1/nobody?sslmode=disable")
	if err != nil {
		t.Fatalf("open lazy db: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func requireDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		dsn = os.Getenv("DATABASE_URL")
	}
	if dsn == "" {
		dsn = "postgres://breakur:breakur@localhost:5432/breakur?sslmode=disable"
	}

	ctx := context.Background()
	conn, err := db.Open(ctx, dsn)
	if err != nil {
		t.Skipf("postgres unavailable, skipping integration test: %v", err)
	}
	if err := db.Migrate(conn); err != nil {
		conn.Close()
		t.Skipf("could not migrate test database: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func createTestUser(t *testing.T, conn *sql.DB) int64 {
	t.Helper()
	suffix := uniqueSuffix()
	var id int64
	err := conn.QueryRowContext(context.Background(),
		`INSERT INTO users (name, username, email, password_hash) VALUES ($1,$2,$3,$4) RETURNING id`,
		"Test User", "u"+suffix, "u"+suffix+"@example.com", "not-a-real-hash").Scan(&id)
	if err != nil {
		t.Fatalf("create test user: %v", err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		// links.user_id is ON DELETE SET NULL, so remove the user's links first
		// to avoid leaving anonymous rows behind.
		_, _ = conn.ExecContext(ctx, `DELETE FROM links WHERE user_id = $1`, id)
		_, _ = conn.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, id)
	})
	return id
}

func uniqueSuffix() string {
	return strconv.FormatInt(time.Now().UnixNano(), 36) + strconv.FormatInt(testCounter.Add(1), 36)
}

func authCookie(sessions *auth.SessionManager, userID int64) *http.Cookie {
	return &http.Cookie{Name: sessionCookie, Value: sessions.Create(userID, time.Now())}
}

func doGet(r *gin.Engine, cookie *http.Cookie, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func doGetBody(r *gin.Engine, cookie *http.Cookie, path string) string {
	w := doGet(r, cookie, path)
	if w.Code != http.StatusOK {
		return ""
	}
	return w.Body.String()
}

func doPost(r *gin.Engine, cookie *http.Cookie, path string, form url.Values) *httptest.ResponseRecorder {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(http.MethodPost, path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func decodeQueryValue(t *testing.T, rawURL, key string) string {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse redirect %q: %v", rawURL, err)
	}
	return parsed.Query().Get(key)
}

func linkID(t *testing.T, conn *sql.DB, code string) int64 {
	t.Helper()
	var id int64
	if err := conn.QueryRowContext(context.Background(), `SELECT id FROM links WHERE short_code = $1`, code).Scan(&id); err != nil {
		t.Fatalf("lookup link %q: %v", code, err)
	}
	return id
}

func linkExists(t *testing.T, conn *sql.DB, code string) bool {
	t.Helper()
	var exists bool
	if err := conn.QueryRowContext(context.Background(), `SELECT EXISTS (SELECT 1 FROM links WHERE short_code = $1)`, code).Scan(&exists); err != nil {
		t.Fatalf("check link %q: %v", code, err)
	}
	return exists
}
