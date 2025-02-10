package routers

import (
	"log"
	"user_service/internal/injectors"

	"github.com/gin-gonic/gin"
)

type AuthRouter struct{}

func (ar *AuthRouter) InitAuthRouter(router *gin.RouterGroup) {
	authController, err := injectors.InitAuthController()
	if err != nil {
		log.Fatalf("cannot init auth controller: %v", err)
	}

	authRouterPublic := router.Group("/auth")
	{
		registrationRouterPublic := authRouterPublic.Group("/register")
		{
			registrationRouterPublic.POST("/send_otp", authController.SendRegistrationOtp)
			registrationRouterPublic.POST("/verify_registration_otp", authController.VerifyRegistrationOtp)
			registrationRouterPublic.POST("/complete_registration", authController.CompleteRegistration)
		}

		authRouterPublic.POST("/login", authController.Login)
		authRouterPublic.POST("/logout", authController.Logout)

		forgotPasswordRouterPublic := authRouterPublic.Group("/forgot_password")
		{
			forgotPasswordRouterPublic.POST("send_otp", authController.SendForgotPasswordOtp)
			forgotPasswordRouterPublic.POST("verify_forgot_password_otp", authController.VerifyForgotPasswordOtp)
			forgotPasswordRouterPublic.PUT("complete_forgot_password", authController.CompleteForgotPassword)
		}

	}
}
