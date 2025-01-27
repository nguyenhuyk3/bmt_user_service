//go:build wireinject

package injectors

import (
	"user_service/db/sqlc"
	"user_service/internal/controllers"
	"user_service/internal/implementations"
	"user_service/internal/injectors/provider"

	"github.com/google/wire"
)

func InitCustomerController() (*controllers.CustomerController, error) {
	wire.Build(
		provider.ProvidePgxPool,
		sqlc.NewStore,
		implementations.NewCustomerService,
		controllers.NewCustomerController,
	)

	return &controllers.CustomerController{}, nil
}
