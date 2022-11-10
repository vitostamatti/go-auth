package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/vitostamatti/jwt-auth/controllers"
)

func AuthRoutes(inRoutes *gin.Engine) {
	inRoutes.POST("users/signup", controllers.Signup())
	inRoutes.POST("users/login", controllers.Login())
}
