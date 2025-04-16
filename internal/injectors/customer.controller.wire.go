//go:build wireinject

package injectors

import (
	"user_service/internal/controllers"
	"user_service/internal/implementations/customer"

	"github.com/google/wire"
)

func InitCustomerController() (*controllers.CustomerController, error) {
	wire.Build(
		dbSet,
		customer.NewCustomerService,
		controllers.NewCustomerController,
	)

	return &controllers.CustomerController{}, nil
}
