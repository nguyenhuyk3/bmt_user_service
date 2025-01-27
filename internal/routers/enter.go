package routers

type RouterGroup struct {
	Auth     AuthRouter
	Customer CustomerRouter
}

var UserServiceRouterGroup = new(RouterGroup)
