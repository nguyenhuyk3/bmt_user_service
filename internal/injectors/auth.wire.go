//go:build wireinject

package injectors

import (
	"user_service/db/sqlc"
	"user_service/internal/controllers"
	"user_service/internal/implementations"
	"user_service/internal/injectors/provider"
	"user_service/utils/token/jwt"

	"github.com/google/wire"
)

func InitAuthController() (*controllers.AuthController, error) {
	wire.Build(
		provider.ProvidePgxPool,
		sqlc.NewStore,
		provider.ProvideSecretKey,
		jwt.NewJWTMaker,
		implementations.NewAuthService,
		controllers.NewAuthController,
	)

	return &controllers.AuthController{}, nil
}
