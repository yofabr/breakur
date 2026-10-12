package router

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"net/http"
	"strings"

	"breakur/internal/auth"

	"github.com/gin-gonic/gin"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
)

// maxUsernameAttempts bounds how many random suffixes we try when the generated
// username is already taken.
const maxUsernameAttempts = 20

// providerNames renders the enabled providers for the startup log line.
func providerNames(providers []auth.Provider) string {
	names := make([]string, 0, len(providers))
	for _, p := range providers {
		names = append(names, p.Name)
	}
	return strings.Join(names, ", ")
}

// listOAuthProviders reports which third-party sign-in methods are configured,
// so the login and signup pages can render the right buttons.
func (s *server) listOAuthProviders(c *gin.Context) {
	if s.providers == nil {
		c.JSON(http.StatusOK, []auth.Provider{})
		return
	}
	c.JSON(http.StatusOK, s.providers)
}

// beginOAuth starts the provider handshake and redirects the browser.
func (s *server) beginOAuth(c *gin.Context) {
	name := c.Param("provider")
	if _, ok := s.oauth[name]; !ok {
		redirectWithError(c, "/login", "That sign-in method is not available.")
		return
	}
	gothic.BeginAuthHandler(c.Writer, gothic.GetContextWithProvider(c.Request, name))
}

// completeOAuth finishes the handshake, resolves the goth user to a breakur
// account, and signs that account in.
func (s *server) completeOAuth(c *gin.Context) {
	name := c.Param("provider")
	label, ok := s.oauth[name]
	if !ok {
		redirectWithError(c, "/login", "That sign-in method is not available.")
		return
	}

	req := gothic.GetContextWithProvider(c.Request, name)
	gothUser, err := gothic.CompleteUserAuth(c.Writer, req)
	if err != nil {
		log.Printf("oauth %s: complete auth: %v", name, err)
		redirectWithError(c, "/login", "Could not sign you in with "+label+". Please try again.")
		return
	}

	userID, err := s.resolveOAuthUser(c.Request.Context(), gothUser)
	if err != nil {
		log.Printf("oauth %s: resolve user: %v", name, err)
		redirectWithError(c, "/login", "Could not sign you in with "+label+". Please try again.")
		return
	}

	s.setSession(c, userID)
	c.Redirect(http.StatusSeeOther, "/dashboard")
}

// resolveOAuthUser maps a provider identity to a breakur user id, creating an
// account on first sight. In order of precedence:
//
//  1. a known (provider, provider_user_id) signs in as that user;
//  2. otherwise the identity is attached to the account owning the email;
//  3. otherwise a fresh account is created and the identity attached to it.
//
// Google and GitHub only expose verified primary emails, so (2) is a trusted
// match. An account created here has no password (password_hash IS NULL).
func (s *server) resolveOAuthUser(ctx context.Context, u goth.User) (int64, error) {
	provider := strings.ToLower(strings.TrimSpace(u.Provider))
	subject := strings.TrimSpace(u.UserID)
	email := strings.ToLower(strings.TrimSpace(u.Email))

	if provider == "" || subject == "" {
		return 0, errors.New("provider returned no account id")
	}
	if email == "" {
		return 0, errors.New("provider returned no email address")
	}

	tx, err := s.conn.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var userID int64
	err = tx.QueryRowContext(ctx,
		`SELECT user_id FROM user_socials WHERE provider = $1 AND provider_user_id = $2`,
		provider, subject).Scan(&userID)
	if err == nil {
		return userID, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}

	err = tx.QueryRowContext(ctx, `SELECT id FROM users WHERE email = $1`, email).Scan(&userID)
	switch {
	case err == nil:
		// Existing account: just attach the new identity.
	case errors.Is(err, sql.ErrNoRows):
		username, uerr := uniqueUsername(ctx, tx, u)
		if uerr != nil {
			return 0, uerr
		}
		if err := tx.QueryRowContext(ctx,
			`INSERT INTO users (name, username, email) VALUES ($1, $2, $3) RETURNING id`,
			displayName(u), username, email).Scan(&userID); err != nil {
			return 0, err
		}
	default:
		return 0, err
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO user_socials (user_id, provider, provider_user_id)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id, provider) DO UPDATE SET provider_user_id = EXCLUDED.provider_user_id`,
		userID, provider, subject); err != nil {
		return 0, err
	}

	return userID, tx.Commit()
}

// uniqueUsername derives a free username from the provider profile.
func uniqueUsername(ctx context.Context, tx *sql.Tx, u goth.User) (string, error) {
	base := sanitizeUsername(usernameSeed(u))
	for attempt := 0; attempt < maxUsernameAttempts; attempt++ {
		candidate := base
		if attempt > 0 {
			suffix, err := generateShortCode(6)
			if err != nil {
				return "", err
			}
			candidate = truncateRunes(base, 32-len(suffix)-1) + "_" + suffix
		}

		var exists bool
		if err := tx.QueryRowContext(ctx,
			`SELECT EXISTS (SELECT 1 FROM users WHERE username = $1)`, candidate).Scan(&exists); err != nil {
			return "", err
		}
		if !exists {
			return candidate, nil
		}
	}
	return "", errors.New("could not generate a unique username")
}

// usernameSeed picks the friendliest available profile field to build from.
func usernameSeed(u goth.User) string {
	for _, candidate := range []string{u.NickName, u.Name, localPart(u.Email)} {
		if strings.TrimSpace(candidate) != "" {
			return candidate
		}
	}
	return "user"
}

// sanitizeUsername maps arbitrary provider data onto the ^[a-z0-9_]{3,32}$
// username rule, collapsing separators and padding short results.
func sanitizeUsername(raw string) string {
	var b strings.Builder
	prevUnderscore := false
	for _, r := range strings.ToLower(raw) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prevUnderscore = false
		case b.Len() > 0 && !prevUnderscore:
			b.WriteByte('_')
			prevUnderscore = true
		}
	}

	name := strings.Trim(b.String(), "_")
	if len(name) > 32 {
		name = strings.TrimRight(name[:32], "_")
	}
	if len(name) < 3 {
		name += strings.Repeat("0", 3-len(name))
	}
	return name
}

// displayName returns the account's human name from the provider profile.
func displayName(u goth.User) string {
	candidates := []string{u.Name, u.NickName, strings.TrimSpace(u.FirstName + " " + u.LastName)}
	for _, candidate := range candidates {
		if candidate = strings.TrimSpace(candidate); candidate != "" {
			return truncateRunes(candidate, 120)
		}
	}
	if local := localPart(u.Email); local != "" {
		return truncateRunes(local, 120)
	}
	return "breakur user"
}

// localPart returns the portion of an email before the @.
func localPart(email string) string {
	if i := strings.IndexByte(email, '@'); i > 0 {
		return email[:i]
	}
	return email
}

// truncateRunes limits s to n runes without splitting a multi-byte character.
func truncateRunes(s string, n int) string {
	if n <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n])
}
