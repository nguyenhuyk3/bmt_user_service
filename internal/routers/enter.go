package routers

import "user_service/internal/routers/auth"

type RouterGroup struct {
	Auth auth.AuthRouter
}

var UserServiceRouteGroup = new(RouterGroup)
