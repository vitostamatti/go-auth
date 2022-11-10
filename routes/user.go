package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/vitostamatti/jwt-auth/controllers"
	"github.com/vitostamatti/jwt-auth/middleware"
)

func UserRoutes(inRoutes *gin.Engine) {
	inRoutes.Use(middleware.Authenticate())
	inRoutes.GET("/users", controllers.GetUsers())
	inRoutes.GET("users/:id", controllers.GetUser())
}
