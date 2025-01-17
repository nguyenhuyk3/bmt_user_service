package initializations

import (
	"user_service/internal/routers"

	"github.com/gin-gonic/gin"
)

func initRouter() *gin.Engine {
	r := gin.Default()
	authRouter := routers.UserServiceRouteGroup.Auth
	mainGroup := r.Group("/v1")
	{
		authRouter.InitAuthRouter(mainGroup)
	}

	return r
}
