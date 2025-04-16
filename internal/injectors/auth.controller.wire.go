//go:build wireinject

package injectors

import (
	"user_service/internal/controllers"
	forgotpassword "user_service/internal/implementations/forgot_password"
	"user_service/internal/implementations/login"
	"user_service/internal/implementations/logout"
	"user_service/internal/implementations/oauth2"
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

		registration.NewRegistrationService,
		forgotpassword.NewForgotPasswordSevice,
		oauth2.NewOAuth2Service,
		login.NewLoginService,
		logout.NewLogoutService,

		provider.ProvideGoogleOAuthConfig,
		provider.ProvideFacebookOAuthConfig,

		controllers.NewAuthController,
	)

	return &controllers.AuthController{}, nil
}
