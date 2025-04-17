package routers

import (
	"log"
	"user_service/internal/injectors"
	"user_service/internal/middlewares"

	"github.com/gin-gonic/gin"
)

type AdminRouter struct{}

func (ar *AdminRouter) InitCustomerRouter(router *gin.RouterGroup, authMiddleware *middlewares.AuthMiddleware) {
	adminController, err := injectors.InitAdminController()
	if err != nil {
		log.Fatalf("cannot init admin controller: %v", err)
	}

	adminRouterPublic := router.Group("/admin")
	{
		inforRouterPublic := adminRouterPublic.Group("/infor").Use(
			authMiddleware.GetAccessToken(),
			authMiddleware.CheckAccessTokenInBlackList(),
			authMiddleware.CheckPermission(),
		)
		{
			inforRouterPublic.GET("/get/:email", adminController.GetAdminInfor)
			inforRouterPublic.POST("/change_user_information", adminController.UpdateAdminInfo)
		}

		adminRouterPublic.POST("/create", adminController.CreateAdminAccount)
	}
}
