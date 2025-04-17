//go:build wireinject

package injectors

import (
	"user_service/internal/controllers"
	"user_service/internal/implementations/admin"

	"github.com/google/wire"
)

func InitAdminController() (*controllers.AdminController, error) {
	wire.Build(
		dbSet,
		admin.NewAdminService,
		controllers.NewAdminController,
	)

	return &controllers.AdminController{}, nil
}
