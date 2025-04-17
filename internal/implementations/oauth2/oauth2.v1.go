package oauth2

import (
	"context"
	"fmt"
	"net/http"
	"user_service/db/sqlc"
	"user_service/dto/request"
	"user_service/dto/response"
	"user_service/global"
	"user_service/internal/services"
	"user_service/utils/cryptor"
	"user_service/utils/token/jwt"
)

type oAuth2Service struct {
	SqlStore sqlc.IStore
	JwtMaker jwt.IMaker
}

// CheckOAuth2UserByEmail implements services.IOAuth2Login.
func (o *oAuth2Service) CheckOAuth2UserByEmail(ctx context.Context, arg request.EmailAndSource) (bool, error) {
	var source sqlc.Sources

	// Map the source string to the appropriate enum value
	switch arg.Source {
	case "google":
		source = sqlc.SourcesGoogle
	case "facebook":
		source = sqlc.SourcesFacebook
	default:
		return false, fmt.Errorf("unsupported source: %s", arg.Source)
	}
	isExists, err := o.SqlStore.CheckAccountExistsByEmailAndSource(ctx,
		sqlc.CheckAccountExistsByEmailAndSourceParams{
			Email: arg.Email,
			Source: sqlc.NullSources{
				Sources: source,
				Valid:   true}})
	if err != nil {
		return false, fmt.Errorf("an error occur when querying to db: %v", err)
	}
	if isExists {
		return isExists, fmt.Errorf("this email has been registered")
	} else {
		return isExists, nil
	}
}

// InserOAuth2User implements services.IOAuth2Login.
func (o *oAuth2Service) InserOAuth2User(ctx context.Context, arg response.OAuth2UserInfo) (int, error) {
	hasedPassword, _ := cryptor.BcryptHashInput(arg.Id)
	err := o.SqlStore.InsertAccountTran(ctx, request.CompleteRegistrationReq{
		Account: request.Account{
			Email:    arg.Email,
			Password: hasedPassword,
			Role:     global.CUSTOMER_ROLE,
		},
		Info: request.Info{
			Name:     arg.Name,
			Sex:      global.MALE,
			BirthDay: "",
		},
	}, true)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("an error occur when insert to db: %v", err)
	}

	return http.StatusOK, nil
}

// ReturnToken implements services.IOAuth2Login.
func (o *oAuth2Service) ReturnToken(ctx context.Context, email string) (response.LoginRes, int, error) {
	accessToken, payload, err := o.JwtMaker.CreateAccessToken(email, global.CUSTOMER_ROLE)
	if err != nil {
		return response.LoginRes{}, http.StatusInternalServerError, fmt.Errorf("an error occur when creating jwt access token: %v", err)
	}
	refreshToken, _, err := o.JwtMaker.CreateRefreshToken(email, global.CUSTOMER_ROLE)
	if err != nil {
		return response.LoginRes{}, http.StatusInternalServerError, fmt.Errorf("an error occur when creating jwt refrest token: %v", err)
	}

	return response.LoginRes{
		AccessToken:   accessToken,
		AccessPayload: payload,
		RefreshToken:  refreshToken,
	}, http.StatusOK, nil
}

func NewOAuth2Service(
	sqlStore sqlc.IStore,
	jwtMaker jwt.IMaker,
) services.IOAuth2 {
	return &oAuth2Service{
		SqlStore: sqlStore,
		JwtMaker: jwtMaker,
	}
}
