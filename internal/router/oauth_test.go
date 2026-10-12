package router

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/markbates/goth"
)

func TestSanitizeUsername(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"spaces become underscores", "Ada Lovelace", "ada_lovelace"},
		{"punctuation collapses", "Ada!!!Lovelace", "ada_lovelace"},
		{"leading and trailing separators trimmed", "_Ada_", "ada"},
		{"too short is padded", "ab", "ab0"},
		{"no usable characters", "!!!@@@", "000"},
		{"truncated to 32", strings.Repeat("a", 40), strings.Repeat("a", 32)},
		{"digits kept", "user_42", "user_42"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeUsername(tt.in)
			if got != tt.want {
				t.Fatalf("sanitizeUsername(%q) = %q, want %q", tt.in, got, tt.want)
			}
			if !usernamePattern.MatchString(got) {
				t.Fatalf("sanitizeUsername(%q) = %q does not match the username rule", tt.in, got)
			}
		})
	}
}

func TestDisplayName(t *testing.T) {
	if got := displayName(goth.User{Name: "Ada Lovelace"}); got != "Ada Lovelace" {
		t.Fatalf("displayName from Name = %q", got)
	}
	if got := displayName(goth.User{NickName: "ada"}); got != "ada" {
		t.Fatalf("displayName from NickName = %q", got)
	}
	if got := displayName(goth.User{Email: "ada@example.com"}); got != "ada" {
		t.Fatalf("displayName from email = %q", got)
	}
	if got := displayName(goth.User{}); got != "breakur user" {
		t.Fatalf("displayName default = %q", got)
	}
}

// TestOAuthProvidersEndpoint proves an unconfigured app advertises no providers.
func TestOAuthProvidersEndpoint(t *testing.T) {
	clearOAuthEnv(t)
	withSecret(t)

	rec := doGet(New(lazyDB(t), nil), nil, "/auth/providers")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if body := strings.TrimSpace(rec.Body.String()); body != "[]" {
		t.Fatalf("body = %q, want []", body)
	}
}

// TestOAuthBeginRedirectsToProvider proves a configured provider hands the
// browser off to the provider's authorization endpoint.
func TestOAuthBeginRedirectsToProvider(t *testing.T) {
	clearOAuthEnv(t)
	t.Setenv("GITHUB_CLIENT_ID", "test-id")
	t.Setenv("GITHUB_CLIENT_SECRET", "test-secret")
	withSecret(t)

	rec := doGet(New(lazyDB(t), nil), nil, "/auth/github")
	if rec.Code != http.StatusTemporaryRedirect {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusTemporaryRedirect)
	}
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "https://github.com/login/oauth/authorize") {
		t.Fatalf("Location = %q, want the GitHub authorize URL", loc)
	}
}

// TestOAuthUnknownProviderIsRejected proves a provider that is not configured
// cannot be triggered, even if goth still knows about it from another test.
func TestOAuthUnknownProviderIsRejected(t *testing.T) {
	clearOAuthEnv(t)
	withSecret(t)

	rec := doGet(New(lazyDB(t), nil), nil, "/auth/facebook")
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "/login?error=") {
		t.Fatalf("Location = %q, want a login error redirect", loc)
	}
}

// TestResolveOAuthUser covers the three resolution paths against a real DB.
func TestResolveOAuthUser(t *testing.T) {
	conn := requireDB(t)
	withSecret(t)
	s := &server{conn: conn}

	suffix := uniqueSuffix()
	email := "oauth-" + suffix + "@example.com"
	subject := "subject-" + suffix
	t.Cleanup(func() {
		_, _ = conn.ExecContext(context.Background(), `DELETE FROM users WHERE email = $1`, email)
	})

	// 1. First sighting creates an account with no password.
	user, err := s.resolveOAuthUser(context.Background(), goth.User{
		Provider: "github", UserID: subject, Email: email, Name: "Ada Lovelace", NickName: "ada",
	})
	if err != nil {
		t.Fatalf("create oauth user: %v", err)
	}

	var username, hash string
	if err := conn.QueryRowContext(context.Background(),
		`SELECT username, COALESCE(password_hash, '') FROM users WHERE id = $1`, user).Scan(&username, &hash); err != nil {
		t.Fatalf("load created user: %v", err)
	}
	if !usernamePattern.MatchString(username) {
		t.Fatalf("username %q does not match the username rule", username)
	}
	if hash != "" {
		t.Fatalf("oauth-only account has a non-NULL password hash")
	}

	var providerUserID string
	if err := conn.QueryRowContext(context.Background(),
		`SELECT provider_user_id FROM user_socials WHERE user_id = $1 AND provider = 'github'`, user).Scan(&providerUserID); err != nil {
		t.Fatalf("load social identity: %v", err)
	}
	if providerUserID != subject {
		t.Fatalf("provider_user_id = %q, want %q", providerUserID, subject)
	}

	// 2. The same identity signs back into the same account.
	again, err := s.resolveOAuthUser(context.Background(), goth.User{Provider: "github", UserID: subject, Email: email})
	if err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if again != user {
		t.Fatalf("second resolve = %d, want %d", again, user)
	}

	// 3. A different provider identity with the same email links to the account.
	linked, err := s.resolveOAuthUser(context.Background(), goth.User{
		Provider: "google", UserID: "google-" + suffix, Email: email, Name: "Ada Lovelace",
	})
	if err != nil {
		t.Fatalf("link by email: %v", err)
	}
	if linked != user {
		t.Fatalf("email-linked resolve = %d, want %d", linked, user)
	}

	var identities int
	if err := conn.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM user_socials WHERE user_id = $1`, user).Scan(&identities); err != nil {
		t.Fatalf("count identities: %v", err)
	}
	if identities != 2 {
		t.Fatalf("linked identities = %d, want 2", identities)
	}
}

// clearOAuthEnv pins the OAuth configuration so a test sees exactly the
// providers it sets up itself, regardless of the host environment.
func clearOAuthEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"OAUTH_BASE_URL",
		"GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET",
		"GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET",
	} {
		t.Setenv(key, "")
	}
}
