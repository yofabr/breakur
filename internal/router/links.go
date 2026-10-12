package router

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"breakur/internal/cache"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	// maxLinksShown caps how many links the dashboard renders at once.
	maxLinksShown = 100
	// shortCodeLength is the length of generated short codes.
	shortCodeLength = 7
	// maxCodeAttempts bounds retries when a generated code collides.
	maxCodeAttempts = 5
)

// shortCodePattern mirrors the links_short_code_fmt database constraint.
var shortCodePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// reservedCodes can never be used as custom short codes because they are real
// application routes.
var reservedCodes = map[string]bool{
	"login":     true,
	"signup":    true,
	"dashboard": true,
	"links":     true,
	"logout":    true,
	"public":    true,
	"auth":      true,
}

// codeAlphabet deliberately excludes characters that are unsafe in URLs.
const codeAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// dashboardLink is one rendered row on the dashboard.
type dashboardLink struct {
	ID      int64
	URL     string
	Code    string
	Short   string
	Created string
}

// dashboardView is the data passed to public/dashboard.html.
type dashboardView struct {
	Links  []dashboardLink
	Error  string
	Notice string
}

func (s *server) showDashboard(c *gin.Context) {
	userID := c.MustGet(contextUserID).(int64)

	rows, err := s.conn.QueryContext(c.Request.Context(), `
		SELECT id, url, short_code, created_at
		FROM links
		WHERE user_id = $1
		ORDER BY created_at DESC, id DESC
		LIMIT $2`, userID, maxLinksShown)
	if err != nil {
		c.String(http.StatusInternalServerError, "could not load your links")
		return
	}
	defer rows.Close()

	base := baseURL(c)
	view := dashboardView{Error: c.Query("error"), Notice: c.Query("notice")}
	for rows.Next() {
		var link dashboardLink
		var createdAt time.Time
		if err := rows.Scan(&link.ID, &link.URL, &link.Code, &createdAt); err != nil {
			c.String(http.StatusInternalServerError, "could not load your links")
			return
		}
		link.Short = base + "/" + link.Code
		link.Created = createdAt.Format("Jan 2, 2006")
		view.Links = append(view.Links, link)
	}
	if err := rows.Err(); err != nil {
		c.String(http.StatusInternalServerError, "could not load your links")
		return
	}

	var buf bytes.Buffer
	if err := s.dashboard.Execute(&buf, view); err != nil {
		c.String(http.StatusInternalServerError, "could not render your dashboard")
		return
	}
	c.Data(http.StatusOK, "text/html; charset=utf-8", buf.Bytes())
}

// warmLink caches a freshly created link so a previously negative-cached code
// becomes live immediately. Cache failures are logged and ignored.
func (s *server) warmLink(ctx context.Context, code, destination string) {
	if cerr := s.cache.Set(ctx, code, destination); cerr != nil {
		log.Printf("cache set %q: %v", code, cerr)
	}
}

func (s *server) createLink(c *gin.Context) {
	userID := c.MustGet(contextUserID).(int64)

	destination, ok := normalizeURL(c.PostForm("url"))
	if !ok {
		redirectWithError(c, "/dashboard", "Enter a valid http:// or https:// destination URL.")
		return
	}

	code, err := validCustomCode(c.PostForm("code"))
	if err != nil {
		redirectWithError(c, "/dashboard", err.Error())
		return
	}

	if code != "" {
		if err := s.insertLink(c.Request.Context(), userID, destination, code); err != nil {
			if isUniqueViolation(err) {
				redirectWithError(c, "/dashboard", "That short code is already taken.")
				return
			}
			redirectWithError(c, "/dashboard", "Could not create your short link. Please try again.")
			return
		}
		s.warmLink(c.Request.Context(), code, destination)
		c.Redirect(http.StatusSeeOther, "/dashboard?notice="+url.QueryEscape("Short link created."))
		return
	}

	for attempt := 0; attempt < maxCodeAttempts; attempt++ {
		candidate, err := generateShortCode(shortCodeLength)
		if err != nil {
			break
		}
		if err := s.insertLink(c.Request.Context(), userID, destination, candidate); err != nil {
			if isUniqueViolation(err) {
				continue
			}
			break
		}
		s.warmLink(c.Request.Context(), candidate, destination)
		c.Redirect(http.StatusSeeOther, "/dashboard?notice="+url.QueryEscape("Short link created."))
		return
	}

	redirectWithError(c, "/dashboard", "Could not create your short link. Please try again.")
}

func (s *server) deleteLink(c *gin.Context) {
	userID := c.MustGet(contextUserID).(int64)

	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id < 1 {
		redirectWithError(c, "/dashboard", "That link does not exist.")
		return
	}

	// The user_id predicate is what enforces ownership: one user can never
	// delete another user's link. Returning the short_code lets us evict it
	// from the shared Redis cache.
	var code string
	err = s.conn.QueryRowContext(c.Request.Context(),
		"DELETE FROM links WHERE id = $1 AND user_id = $2 RETURNING short_code",
		id, userID).Scan(&code)
	if errors.Is(err, sql.ErrNoRows) {
		redirectWithError(c, "/dashboard", "That link does not exist.")
		return
	}
	if err != nil {
		redirectWithError(c, "/dashboard", "Could not delete that link. Please try again.")
		return
	}

	if cerr := s.cache.Delete(c.Request.Context(), code); cerr != nil {
		log.Printf("cache delete %q: %v", code, cerr)
	}

	c.Redirect(http.StatusSeeOther, "/dashboard")
}

func (s *server) redirectLink(c *gin.Context) {
	code := c.Param("shortCode")
	ctx := c.Request.Context()

	// Cache-aside read: a hit short-circuits the Postgres query, a negative hit
	// is a known-404, and any cache error is logged and treated as a miss so
	// redirects always fall back to PostgreSQL (fail open).
	destination, result, err := s.cache.Get(ctx, code)
	if err != nil {
		log.Printf("cache get %q: %v", code, err)
	}
	switch result {
	case cache.LookupHit:
		c.Redirect(http.StatusFound, destination)
		return
	case cache.LookupNegative:
		c.Data(http.StatusNotFound, "text/html; charset=utf-8", []byte(notFoundPage))
		return
	}

	err = s.conn.QueryRowContext(ctx,
		"SELECT url FROM links WHERE short_code = $1", code).Scan(&destination)
	if errors.Is(err, sql.ErrNoRows) {
		if cerr := s.cache.SetMissing(ctx, code); cerr != nil {
			log.Printf("cache mark missing %q: %v", code, cerr)
		}
		c.Data(http.StatusNotFound, "text/html; charset=utf-8", []byte(notFoundPage))
		return
	}
	if err != nil {
		c.String(http.StatusInternalServerError, "could not resolve that short link")
		return
	}

	if cerr := s.cache.Set(ctx, code, destination); cerr != nil {
		log.Printf("cache set %q: %v", code, cerr)
	}
	c.Redirect(http.StatusFound, destination)
}

func (s *server) insertLink(ctx context.Context, userID int64, destination, code string) error {
	_, err := s.conn.ExecContext(ctx, "INSERT INTO links (user_id, url, short_code) VALUES ($1, $2, $3)", userID, destination, code)
	return err
}

// normalizeURL trims and validates a destination, returning a cleaned URL that
// only uses the http or https scheme.
func normalizeURL(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", false
	}
	if parsed.Host == "" {
		return "", false
	}
	return parsed.String(), true
}

// validCustomCode validates an optional custom short code. An empty code is
// valid and means "generate one".
func validCustomCode(code string) (string, error) {
	code = strings.TrimSpace(code)
	if code == "" {
		return "", nil
	}
	if !shortCodePattern.MatchString(code) {
		return "", errors.New("Short codes may only use 1–64 letters, numbers, hyphens, or underscores.")
	}
	if reservedCodes[strings.ToLower(code)] {
		return "", errors.New("That short code is reserved. Pick another one.")
	}
	return code, nil
}

// generateShortCode returns a cryptographically random code from codeAlphabet.
func generateShortCode(length int) (string, error) {
	limit := big.NewInt(int64(len(codeAlphabet)))
	code := make([]byte, length)
	for i := range code {
		n, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return "", err
		}
		code[i] = codeAlphabet[n.Int64()]
	}
	return string(code), nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// baseURL reconstructs the scheme and host the browser used so locally created
// links work without a hard-coded production domain.
func baseURL(c *gin.Context) string {
	scheme := "http"
	if c.Request.TLS != nil {
		scheme = "https"
	}
	if forwarded := c.GetHeader("X-Forwarded-Proto"); forwarded != "" {
		scheme = strings.ToLower(strings.TrimSpace(strings.Split(forwarded, ",")[0]))
	}
	return scheme + "://" + c.Request.Host
}

const notFoundPage = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Link not found — breakur</title>
  </head>
  <body style="margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f6f1e8;color:#111;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;padding:1.25rem">
    <main style="width:100%;max-width:32rem;border:4px solid #111;background:#ff5c35;padding:2.5rem;box-shadow:12px 12px 0 #111">
      <p style="margin:0 0 1rem;font-size:.75rem;font-weight:700;letter-spacing:.16em;text-transform:uppercase">404 / gone</p>
      <h1 style="margin:0;font-size:2.5rem;line-height:.9;letter-spacing:-.08em">NOTHING<br />TO BREAK.</h1>
      <p style="margin:1.5rem 0 0;font-size:1rem;font-weight:700">That short link does not exist.</p>
      <p style="margin:1.5rem 0 0;border-top:3px solid #111;padding-top:1.25rem">
        <a style="color:#111;font-size:.875rem;font-weight:700;text-transform:uppercase" href="/">Make a short link →</a>
      </p>
    </main>
  </body>
</html>
`
