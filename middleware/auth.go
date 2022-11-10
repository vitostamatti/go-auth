package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vitostamatti/jwt-auth/utils"
)

func Authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.Request.Header.Get("token")
		if token == "" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "no authorization header provided"})
			c.Abort()
			return
		}
		claims, err := utils.ValidateToken(token)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			c.Abort()
			return
		}
		c.Set("email", claims.Email)
		c.Set("first_name", claims.FirstName)
		c.Set("last_name", claims.LastName)
		c.Set("user_id", claims.UserId)
		c.Set("user_type", claims.UserType)

		c.Next()
	}
}
