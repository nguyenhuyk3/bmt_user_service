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

type CustomerController struct {
	CustomerService services.ICustomer
}

func NewCustomerController(customerService services.ICustomer) *CustomerController {
	return &CustomerController{
		CustomerService: customerService,
	}
}

func (cc *CustomerController) GetInfor(c *gin.Context) {
	email := c.Param("email")
	if email == "" {
		responses.FailureResponse(c, http.StatusBadRequest, "email parameter is required")
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	data, status, err := cc.CustomerService.GetInfor(ctx, request.GetInforReq{Email: email})
	if err != nil {
		responses.FailureResponse(c, status, err.Error())
		return
	}

	responses.SuccessResponse(c, http.StatusOK, "get infor perform successfully", data)
}

func (cc *CustomerController) UpdateUserInfo(c *gin.Context) {
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

	status, err := cc.CustomerService.UpdateUserInfor(ctx, req)
	if err != nil {
		responses.FailureResponse(c, status, err.Error())
		return
	}

	responses.SuccessResponse(c, http.StatusOK, "change infor perform successfully", nil)
}
