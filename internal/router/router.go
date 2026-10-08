// Package router wires up the Gin engine and all HTTP routes.
package router

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// indexFile is the page served at the root path.
const indexFile = "public/index.html"

// New builds the Gin engine with all routes registered.
func New() *gin.Engine {
	r := gin.Default()

	// The index page.
	r.GET("/", func(c *gin.Context) {
		c.File(indexFile)
	})

	// Serve the rest of public/ (css, js, images, ...) alongside it.
	r.StaticFS("/public", http.Dir("public"))

	return r
}
