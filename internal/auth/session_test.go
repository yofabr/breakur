package auth

import (
	"path/filepath"
	"testing"
	"time"
)

func TestGeneratedSecretPersistsAcrossManagers(t *testing.T) {
	t.Setenv("AUTH_SESSION_KEY_FILE", filepath.Join(t.TempDir(), "session.key"))

	first, err := NewSessionManager("")
	if err != nil {
		t.Fatalf("first manager: %v", err)
	}
	cookie := first.Create(42, time.Now())

	// Simulate a restart: a brand new manager must accept the old cookie.
	second, err := NewSessionManager("")
	if err != nil {
		t.Fatalf("second manager: %v", err)
	}
	userID, err := second.UserID(cookie, time.Now())
	if err != nil {
		t.Fatalf("session did not survive restart: %v", err)
	}
	if userID != 42 {
		t.Fatalf("userID = %d, want 42", userID)
	}
}

func TestExplicitSecretWins(t *testing.T) {
	// An explicit secret is used even when a key file is configured.
	t.Setenv("AUTH_SESSION_KEY_FILE", filepath.Join(t.TempDir(), "session.key"))

	a, err := NewSessionManager("explicit-secret")
	if err != nil {
		t.Fatalf("manager a: %v", err)
	}
	b, err := NewSessionManager("explicit-secret")
	if err != nil {
		t.Fatalf("manager b: %v", err)
	}
	cookie := a.Create(7, time.Now())
	if id, err := b.UserID(cookie, time.Now()); err != nil || id != 7 {
		t.Fatalf("matching secrets rejected: id=%d err=%v", id, err)
	}

	c, err := NewSessionManager("different-secret")
	if err != nil {
		t.Fatalf("manager c: %v", err)
	}
	if _, err := c.UserID(cookie, time.Now()); err == nil {
		t.Fatal("a different secret accepted a foreign cookie")
	}
}

func TestExpiredSessionRejected(t *testing.T) {
	m, err := NewSessionManager("secret")
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	cookie := m.Create(1, time.Now().Add(-(SessionDuration + time.Hour)))
	if _, err := m.UserID(cookie, time.Now()); err == nil {
		t.Fatal("expired session was accepted")
	}
}
