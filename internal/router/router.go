// Package router wires up the Gin engine and all HTTP routes.
package router

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

const (
	indexFile  = "public/index.html"
	loginFile  = "public/login.html"
	signupFile = "public/signup.html"
)

// New builds the Gin engine with all routes registered.
func New() *gin.Engine {
	r := gin.Default()

	// Static pages.
	r.GET("/", func(c *gin.Context) {
		c.File(indexFile)
	})

	r.GET("/login", func(c *gin.Context) {
		c.File(loginFile)
	})

	r.GET("/signup", func(c *gin.Context) {
		c.File(signupFile)
	})

	// Serve the rest of public/ (css, js, images, ...) alongside it.
	r.StaticFS("/public", http.Dir("public"))

	return r
}
