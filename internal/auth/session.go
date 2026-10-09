// Package auth provides small, signed browser sessions for breakur.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"time"
)

const SessionDuration = 7 * 24 * time.Hour

// SessionManager creates tamper-evident cookies. Set AUTH_SESSION_SECRET in
// production so sessions survive application restarts.
type SessionManager struct {
	secret []byte
}

func NewSessionManager(secret string) (*SessionManager, error) {
	if secret != "" {
		return &SessionManager{secret: []byte(secret)}, nil
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return &SessionManager{secret: key}, nil
}

// Create returns a signed session value for userID.
func (m *SessionManager) Create(userID int64, now time.Time) string {
	payload := strconv.FormatInt(userID, 10) + "." + strconv.FormatInt(now.Add(SessionDuration).Unix(), 10)
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
