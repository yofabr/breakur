// Package auth provides small, signed browser sessions for breakur.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	// SessionDuration is the session lifetime used when AUTH_SESSION_TTL is unset.
	SessionDuration = 7 * 24 * time.Hour

	// keyFileEnv overrides where the generated session key is stored.
	keyFileEnv = "AUTH_SESSION_KEY_FILE"

	// sessionTTLEnv overrides the session lifetime. It accepts Go duration
	// syntax, for example "168h", "30m" or "90s".
	sessionTTLEnv = "AUTH_SESSION_TTL"
)

// SessionManager creates tamper-evident cookies. Set AUTH_SESSION_SECRET in
// production so sessions survive application restarts.
type SessionManager struct {
	secret []byte
	ttl    time.Duration
}

func NewSessionManager(secret string) (*SessionManager, error) {
	ttl := sessionTTL()

	if secret != "" {
		return &SessionManager{secret: []byte(secret), ttl: ttl}, nil
	}

	// No explicit secret: load a persisted key so development sessions survive
	// restarts, generating and storing one on first use.
	key, err := loadOrCreateSecret()
	if err != nil {
		return nil, err
	}
	return &SessionManager{secret: key, ttl: ttl}, nil
}

// Key returns the signing key. Cookie-backed helpers (such as the OAuth state
// cookie) share it so their sessions survive application restarts too.
func (m *SessionManager) Key() []byte {
	return m.secret
}

// Duration returns how long a session stays valid. Login cookies and the OAuth
// state cookie use it so both expire with the configured AUTH_SESSION_TTL.
func (m *SessionManager) Duration() time.Duration {
	return m.ttl
}

// Create returns a signed session value for userID.
func (m *SessionManager) Create(userID int64, now time.Time) string {
	payload := strconv.FormatInt(userID, 10) + "." + strconv.FormatInt(now.Add(m.ttl).Unix(), 10)
	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(payload))
	return payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// UserID verifies a session value and returns the logged-in user ID.
func (m *SessionManager) UserID(value string, now time.Time) (int64, error) {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return 0, errors.New("invalid session")
	}

	payload := parts[0] + "." + parts[1]
	provided, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return 0, errors.New("invalid session")
	}
	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(payload))
	if !hmac.Equal(provided, mac.Sum(nil)) {
		return 0, errors.New("invalid session")
	}

	userID, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || userID < 1 {
		return 0, errors.New("invalid session")
	}
	expiresAt, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || now.Unix() > expiresAt {
		return 0, errors.New("expired session")
	}
	return userID, nil
}

// sessionTTL reads the configured session lifetime from AUTH_SESSION_TTL,
// falling back to SessionDuration when it is unset or not a positive duration.
func sessionTTL() time.Duration {
	v := strings.TrimSpace(os.Getenv(sessionTTLEnv))
	if v == "" {
		return SessionDuration
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		log.Printf("%s=%q is not a positive duration; using %s", sessionTTLEnv, v, SessionDuration)
		return SessionDuration
	}
	return d
}

// defaultKeyPath chooses where the auto-generated session key lives. The
// AUTH_SESSION_KEY_FILE environment variable wins, then the user config
// directory, then the OS temp directory.
func defaultKeyPath() (string, error) {
	if path := os.Getenv(keyFileEnv); path != "" {
		return path, nil
	}
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "breakur", "session.key"), nil
	}
	return filepath.Join(os.TempDir(), "breakur-session.key"), nil
}

// loadOrCreateSecret reads the persisted key, creating a fresh one when the
// file is missing or unreadable. Failing to persist is not fatal: the key is
// still returned for use in memory.
func loadOrCreateSecret() ([]byte, error) {
	path, err := defaultKeyPath()
	if err != nil {
		return nil, err
	}

	if data, err := os.ReadFile(path); err == nil && len(data) >= 32 {
		return data, nil
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return key, nil
	}
	_ = os.WriteFile(path, key, 0o600)
	return key, nil
}
