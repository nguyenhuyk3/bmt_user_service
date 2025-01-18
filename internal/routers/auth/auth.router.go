package auth

import (
	"user_service/internal/controllers"
	"user_service/internal/implementations"

	"github.com/gin-gonic/gin"
)

type AuthRouter struct{}

func (ar *AuthRouter) InitAuthRouter(router *gin.RouterGroup) {
	authService := implementations.NewAuthService()
	authController := controllers.NewAuthController(authService)
	authRouterPublic := router.Group("/auth")
	{
		registerRouterPublic := authRouterPublic.Group("/register")
		{
			registerRouterPublic.POST("/send_otp", authController.SendOtp)
			registerRouterPublic.POST("/verify_otp", authController.VerifyOtp)
		}

	}
}
