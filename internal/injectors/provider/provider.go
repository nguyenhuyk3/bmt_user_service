package provider

import (
	"user_service/global"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/google"
)

func ProvidePgxPool() *pgxpool.Pool {
	return global.Postgresql
}

func ProvideSecretKey() string {
	return global.Config.Server.SercetKey
}

func ProvideGoogleOAuthConfig() global.GoogleOAuthConfig {
	return &oauth2.Config{
		ClientID:     global.Config.ServiceSetting.GoogleOAuth2.ClientId,
		ClientSecret: global.Config.ServiceSetting.GoogleOAuth2.ClientSecret,
		RedirectURL:  global.Config.ServiceSetting.GoogleOAuth2.RedirectUrl,
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}
}

func ProvideFacebookOAuthConfig() global.FacebookOAuthConfig {
	return &oauth2.Config{
		ClientID:     global.Config.ServiceSetting.FacebookOAuth2.AppId,
		ClientSecret: global.Config.ServiceSetting.FacebookOAuth2.AppSecret,
		RedirectURL:  global.Config.ServiceSetting.FacebookOAuth2.RedirectUrl,
		Scopes:       []string{"email", "public_profile"},
		Endpoint:     facebook.Endpoint,
	}
}
