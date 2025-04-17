package routers

type RouterGroup struct {
	Auth     AuthRouter
	Customer CustomerRouter
	Admin    AdminRouter
}

var UserServiceRouterGroup = new(RouterGroup)
