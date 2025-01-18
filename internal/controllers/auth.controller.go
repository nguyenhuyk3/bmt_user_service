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

func (ac *authController) SendOTP(c *gin.Context) {
	var req request.SendOTPReq
	if err := c.ShouldBindJSON(&req); err != nil {
		responses.FailureResponse(c, http.StatusBadRequest, "request is invalid")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	status, err := ac.AuthService.SendOTP(ctx, req)
	if err != nil {
		responses.FailureResponse(c, status, err.Error())
		return
	}

	responses.SuccessResponse(c, http.StatusOK, "register perform successfully", nil)
}
