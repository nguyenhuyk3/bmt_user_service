package controllers

import (
	"context"
	"net/http"
	"time"
	"user_service/dto/request"
	"user_service/global"
	"user_service/internal/responses"
	"user_service/internal/services"

	"github.com/gin-gonic/gin"
)

type AdminController struct {
	AdminService services.IAdmin
}

func NewAdminController(adminService services.IAdmin) *AdminController {
	return &AdminController{
		AdminService: adminService,
	}
}

func (ac *AdminController) GetAdminInfor(c *gin.Context) {
	email := c.Param("email")
	if email == "" {
		responses.FailureResponse(c, http.StatusBadRequest, "email parameter is required")
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	data, status, err := ac.AdminService.GetInfor(ctx,
		request.GetInforReq{
			Email: email})
	if err != nil {
		responses.FailureResponse(c, status, err.Error())
		return
	}

	responses.SuccessResponse(c, http.StatusOK, "get infor perform successfully", data)
}

func (ca *AdminController) UpdateAdminInfo(c *gin.Context) {
	email := c.GetString("email")
	if email == "" {
		responses.FailureResponse(c, http.StatusBadRequest, "email is not empty")
		return
	}

	var req request.ChangeInforReq
	if err := c.ShouldBindJSON(&req); err != nil {
		responses.FailureResponse(c, http.StatusBadRequest, "request is invalid")
		return
	}

	req.Email = email

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	status, err := ca.AdminService.UpdateUserInfor(ctx, req)
	if err != nil {
		responses.FailureResponse(c, status, err.Error())
		return
	}

	responses.SuccessResponse(c, http.StatusOK, "change infor perform successfully", nil)
}

func (ca *AdminController) CreateAdminAccount(c *gin.Context) {
	var req request.CreateAdminAccountReq
	if err := c.ShouldBindJSON(&req); err != nil {
		responses.FailureResponse(c, http.StatusBadRequest, "request is invalid")
		return
	}

	if req.Key != global.Config.Server.KeyForAdmin {
		responses.FailureResponse(c, http.StatusBadRequest, "key is invalid")
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	status, err := ca.AdminService.CreateAdminAccount(ctx, req)
	if err != nil {
		responses.FailureResponse(c, status, err.Error())
		return
	}

	responses.SuccessResponse(c, http.StatusOK, "create manage account perform successfully", nil)
}
