package controllers

import (
	"context"
	"net/http"
	"time"
	"user_service/dto/request"
	"user_service/internal/responses"
	"user_service/internal/services"

	"github.com/gin-gonic/gin"
)

type AuthController struct {
	AuthService services.IAuth
}

func NewAuthController(authService services.IAuth) *AuthController {
	return &AuthController{
		AuthService: authService,
	}
}

func (ac *AuthController) SendRegistrationOtp(c *gin.Context) {
	var req request.SendOtpReq
	if err := c.ShouldBindJSON(&req); err != nil {
		responses.FailureResponse(c, http.StatusBadRequest, "request is invalid")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	status, err := ac.AuthService.SendRegistrationOtp(ctx, req)
	if err != nil {
		responses.FailureResponse(c, status, err.Error())
		return
	}

	responses.SuccessResponse(c, http.StatusOK, "send otp perform successfully", nil)
}

func (ac *AuthController) VerifyRegistrationOtp(c *gin.Context) {
	var req request.VerifyOtpReq
	if err := c.ShouldBindJSON(&req); err != nil {
		responses.FailureResponse(c, http.StatusBadRequest, "request is invalid")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	status, err := ac.AuthService.VerifyRegistrationOtp(ctx, req)
	if err != nil {
		responses.FailureResponse(c, status, err.Error())
		return
	}

	responses.SuccessResponse(c, http.StatusOK, "verify otp perform successfully", nil)
}

func (ac *AuthController) CompleteRegistration(c *gin.Context) {
	var req request.CompleteRegistrationReq
	if err := c.ShouldBindJSON(&req); err != nil {
		responses.FailureResponse(c, http.StatusBadRequest, "request is invalid")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	status, err := ac.AuthService.CompleteRegistration(ctx, req)
	if err != nil {
		responses.FailureResponse(c, status, err.Error())
		return
	}

	responses.SuccessResponse(c, http.StatusOK, "registration perform successfully", nil)
}

func (ac *AuthController) Login(c *gin.Context) {
	var req request.LoginReq
	if err := c.ShouldBindJSON(&req); err != nil {
		responses.FailureResponse(c, http.StatusBadRequest, "request is invalid")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	data, status, err := ac.AuthService.Login(ctx, req)
	if err != nil {
		responses.FailureResponse(c, status, err.Error())
		return
	}

	responses.SuccessResponse(c, http.StatusOK, "login perform successfully", data)
}

func (ac *AuthController) SendForgotPasswordOtp(c *gin.Context) {
	var req request.SendOtpReq
	if err := c.ShouldBindJSON(&req); err != nil {
		responses.FailureResponse(c, http.StatusBadRequest, "request is invalid")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	status, err := ac.AuthService.SendForgotPasswordOtp(ctx, req)
	if err != nil {
		responses.FailureResponse(c, status, err.Error())
		return
	}

	responses.SuccessResponse(c, http.StatusOK, "send otp perform successfully", nil)
}

func (ac *AuthController) VerifyForgotPasswordOtp(c *gin.Context) {
	var req request.VerifyOtpReq
	if err := c.ShouldBindJSON(&req); err != nil {
		responses.FailureResponse(c, http.StatusBadRequest, "request is invalid")
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	status, err := ac.AuthService.VerifyForgotPasswordOtp(ctx, req)
	if err != nil {
		responses.FailureResponse(c, status, err.Error())
		return
	}

	responses.SuccessResponse(c, http.StatusOK, "verifying otp for forgot password perform successfully", nil)
}

func (ac *AuthController) CompleteForgotPassword(c *gin.Context) {
	var req request.CompleteForgotPasswordReq
	if err := c.ShouldBindJSON(&req); err != nil {
		responses.FailureResponse(c, http.StatusBadRequest, "request is invalid")
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	status, err := ac.AuthService.CompleForgotPassword(ctx, req)
	if err != nil {
		responses.FailureResponse(c, status, err.Error())
		return
	}

	responses.SuccessResponse(c, http.StatusOK, "updating password perform successfully", nil)
}

func (ac *AuthController) Logout(c *gin.Context) {
	token := c.GetString("token")
	if token == "" {
		responses.FailureResponse(c, http.StatusBadRequest, "request is not exist")
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	status, err := ac.AuthService.Logout(ctx, request.LogoutReq{
		Token: token,
	})
	if err != nil {
		responses.FailureResponse(c, status, err.Error())
		return
	}

	responses.SuccessResponse(c, http.StatusOK, "logout perform successfully", nil)
}
