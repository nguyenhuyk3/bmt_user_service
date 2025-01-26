package auth

import (
	"user_service/db/sqlc"
	"user_service/global"
	"user_service/internal/controllers"
	"user_service/internal/implementations"
	"user_service/utils/token/jwt"

	"github.com/gin-gonic/gin"
)

type AuthRouter struct{}

func (ar *AuthRouter) InitAuthRouter(router *gin.RouterGroup) {
	sqlStore := sqlc.NewStore(global.Postgresql)
	jwtMaker, _ := jwt.NewJWTMaker(global.Config.Server.SercetKey)
	authService := implementations.NewAuthService(sqlStore, jwtMaker)
	authController := controllers.NewAuthController(authService)
	authRouterPublic := router.Group("/auth")
	{
		registrationRouterPublic := authRouterPublic.Group("/register")
		{
			registrationRouterPublic.POST("/send_otp", authController.SendRegistrationOtp)
			registrationRouterPublic.POST("/verify_registration_otp", authController.VerifyRegistrationOtp)
			registrationRouterPublic.POST("/complete_registration", authController.CompleteRegistration)
		}

		authRouterPublic.POST("/login", authController.Login)

		forgotPasswordRouterPublic := authRouterPublic.Group("/forgot_password")
		{
			forgotPasswordRouterPublic.POST("send_otp", authController.SendForgotPasswordOtp)
			forgotPasswordRouterPublic.POST("verify_forgot_password_otp", authController.VerifyForgotPasswordOtp)
			forgotPasswordRouterPublic.PUT("complete_forgot_password", authController.CompleteForgotPassword)
		}
	}
}
