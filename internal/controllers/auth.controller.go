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

type authController struct {
	AuthService services.IAuth
}

func NewAuthController(authService services.IAuth) *authController {
	return &authController{
		AuthService: authService,
	}
}

func (ac *authController) SendOtp(c *gin.Context) {
	var req request.SendOtpReq
	if err := c.ShouldBindJSON(&req); err != nil {
		responses.FailureResponse(c, http.StatusBadRequest, "request is invalid")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	status, err := ac.AuthService.SendOtp(ctx, req)
	if err != nil {
		responses.FailureResponse(c, status, err.Error())
		return
	}

	responses.SuccessResponse(c, http.StatusOK, "send otp perform successfully", nil)
}

func (ac *authController) VerifyOtp(c *gin.Context) {
	var req request.VerifyOtpReq
	if err := c.ShouldBindJSON(&req); err != nil {
		responses.FailureResponse(c, http.StatusBadRequest, "request is invalid")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	status, err := ac.AuthService.VerifyOtp(ctx, req)
	if err != nil {
		responses.FailureResponse(c, status, err.Error())
		return
	}

	responses.SuccessResponse(c, http.StatusOK, "verify otp perform successfully", nil)
}

func (ac *authController) CompleteRegistration(c *gin.Context) {
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

func (ac *authController) Login(c *gin.Context) {

}
