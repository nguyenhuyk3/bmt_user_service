//go:build wireinject

package injectors

import (
	"user_service/internal/middlewares"

	"github.com/google/wire"
)

func InitAuthMiddleware() (*middlewares.AuthMiddleware, error) {
	wire.Build(
		jwtSet,
		redisSet,
		middlewares.NewAuthMiddleware,
	)

	return &middlewares.AuthMiddleware{}, nil
}
