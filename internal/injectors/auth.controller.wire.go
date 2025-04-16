//go:build wireinject

package injectors

import (
	"user_service/internal/controllers"
	"user_service/internal/implementations"
	"user_service/internal/implementations/registration"
	"user_service/internal/injectors/provider"

	"github.com/google/wire"
)

func InitAuthController() (*controllers.AuthController, error) {
	wire.Build(
		dbSet,
		jwtSet,
		redisSet,
		kafkaSet,
		implementations.NewAuthService,
		registration.NewRegistrationService,

		provider.ProvideGoogleOAuthConfig,
		provider.ProvideFacebookOAuthConfig,

		controllers.NewAuthController,
	)

	return &controllers.AuthController{}, nil
}
