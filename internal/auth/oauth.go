// This file wires up third-party (OAuth) sign-in via goth.
package auth

import (
	"os"
	"strings"
	"time"

	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/github"
	"github.com/markbates/goth/providers/google"
)

// Provider is a configured sign-in method exposed to the login UI.
type Provider struct {
	Name  string `json:"name"`
	Label string `json:"label"`
}

// ConfigureOAuth initialises goth/gothic. The gothic state cookie is signed
// with the same key as the login session, and the cookie options follow the
// app's secure-cookie setting. Providers are registered only when their client
// ID and secret are present, so an unconfigured provider is simply absent.
//
// baseURL is the public root used to build provider callback URLs, for example
// https://breakur.example, producing https://breakur.example/auth/github/callback.
//
// ttl bounds how long the in-flight OAuth state cookie stays valid.
func ConfigureOAuth(baseURL string, key []byte, secureCookies bool, ttl time.Duration) []Provider {
	store := sessions.NewCookieStore(key)
	store.Options.HttpOnly = true
	store.Options.Secure = secureCookies
	store.Options.Path = "/"
	store.Options.MaxAge = int(ttl.Seconds())
	gothic.Store = store

	var providers []Provider
	if id, secret := os.Getenv("GITHUB_CLIENT_ID"), os.Getenv("GITHUB_CLIENT_SECRET"); id != "" && secret != "" {
		goth.UseProviders(github.New(id, secret, callbackURL(baseURL, "github")))
		providers = append(providers, Provider{Name: "github", Label: "GitHub"})
	}
	if id, secret := os.Getenv("GOOGLE_CLIENT_ID"), os.Getenv("GOOGLE_CLIENT_SECRET"); id != "" && secret != "" {
		goth.UseProviders(google.New(id, secret, callbackURL(baseURL, "google")))
		providers = append(providers, Provider{Name: "google", Label: "Google"})
	}
	return providers
}

// callbackURL builds the provider callback registered with goth.
func callbackURL(baseURL, name string) string {
	return strings.TrimRight(baseURL, "/") + "/auth/" + name + "/callback"
}
