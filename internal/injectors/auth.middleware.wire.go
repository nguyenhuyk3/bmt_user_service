//go:build wireinject

package injectors

import (
	"user_service/internal/injectors/provider"
	"user_service/internal/middlewares"
	"user_service/utils/token/jwt"

	"github.com/google/wire"
)

func InitAuthMiddleware() (*middlewares.AuthMiddleware, error) {
	wire.Build(
		provider.ProvideSecretKey,
		jwt.NewJWTMaker,
		middlewares.NewAuthMiddleware,
	)

	return &middlewares.AuthMiddleware{}, nil
}
