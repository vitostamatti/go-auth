package main

import (
	"os"

	"github.com/gin-gonic/gin"
	"github.com/vitostamatti/jwt-auth/routes"
)

func main() {
	port := os.Getenv("PORT")

	if port == "" {
		port = "8000"
	}

	router := gin.New()
	router.Use(gin.Logger())
	// router := gin.Default()

	router.SetTrustedProxies([]string{"localhost", "*"})

	router.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{"success": "Hello"})
	})
	routes.AuthRoutes(router)
	routes.UserRoutes(router)

	router.Run(":" + port)
}
