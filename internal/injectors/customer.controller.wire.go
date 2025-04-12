//go:build wireinject

package injectors

import (
	"user_service/internal/controllers"
	"user_service/internal/implementations"

	"github.com/google/wire"
)

func InitCustomerController() (*controllers.CustomerController, error) {
	wire.Build(
		dbSet,
		implementations.NewCustomerService,
		controllers.NewCustomerController,
	)

	return &controllers.CustomerController{}, nil
}
