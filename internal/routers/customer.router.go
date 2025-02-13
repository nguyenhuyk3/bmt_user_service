package routers

import (
	"log"
	"user_service/internal/injectors"
	"user_service/internal/middlewares"

	"github.com/gin-gonic/gin"
)

type CustomerRouter struct{}

func (cr *CustomerRouter) InitCustomerRouter(router *gin.RouterGroup, authMiddleware *middlewares.AuthMiddleware) {
	customerController, err := injectors.InitCustomerController()
	if err != nil {
		log.Fatalf("cannot init customer controller: %v", err)
	}

	customerRouterPublic := router.Group("/customer")
	{
		infoRouterPublic := customerRouterPublic.Group("/infor").Use(
			authMiddleware.GetAccessToken(),
			authMiddleware.CheckAccessTokenInBlackList(),
			authMiddleware.CheckPermission(),
		)
		{
			infoRouterPublic.GET("/get/:email", customerController.GetInfor)
		}
	}
}
