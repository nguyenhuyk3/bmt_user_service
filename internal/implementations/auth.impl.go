package implementations

import (
	"context"
	"fmt"
	"net/http"
	"time"
	"user_service/db/sqlc"
	"user_service/dto/request"
	"user_service/dto/response"
	"user_service/global"
	"user_service/internal/services"
	"user_service/utils/cryptor"
	"user_service/utils/token/jwt"

	"github.com/jackc/pgx/v5/pgtype"
)

type authService struct {
	SqlStore      sqlc.IStore
	JwtMaker      jwt.IMaker
	RedisClient   services.IRedis
	MessageBroker services.IMessageBroker
}

func NewAuthService(
	sqlStore sqlc.IStore,
	jwtMaker jwt.IMaker,
	redisClient services.IRedis,
	messageBroker services.IMessageBroker) services.IAuth {
	return &authService{
		SqlStore:      sqlStore,
		JwtMaker:      jwtMaker,
		RedisClient:   redisClient,
		MessageBroker: messageBroker,
	}
}

const (
	ten_minutes   = 10
	three_minutes = 3
	three_hours   = 3 * 60
)

// Logout implements services.IAuth.
func (a *authService) Logout(ctx context.Context, email string) (int, error) {
	_, err := a.SqlStore.UpdateAction(ctx, sqlc.UpdateActionParams{
		Email: email,
		LoginAt: pgtype.Timestamptz{
			Valid: false,
		},
		LogoutAt: pgtype.Timestamptz{
			Time:  time.Now(),
			Valid: true,
		},
	})
	if err != nil {
		return http.StatusInternalServerError, err
	}

	return http.StatusOK, nil
}

// InsertGoogleUser implements services.IAuth.
func (a *authService) InserOAuth2UsertUser(ctx context.Context, arg response.OAuth2UserInfo) (int, error) {
	hasedPassword, _ := cryptor.BcryptHashInput(arg.Id)
	err := a.SqlStore.InsertAccountTran(ctx, request.CompleteRegistrationReq{
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

// CheckOAuth2UserByEmail implements services.IAuth.
func (a *authService) CheckOAuth2UserByEmail(ctx context.Context, email string) (bool, error) {
	isExists, err := a.SqlStore.CheckAccountExistsByEmail(ctx, email)
	if err != nil {
		return false, fmt.Errorf("an error occur when querying to db: %v", err)
	}
	if isExists {
		return isExists, fmt.Errorf("this email has been registered")
	} else {
		return isExists, nil
	}
}

// ReturnToken implements services.IAuth.
func (a *authService) ReturnToken(ctx context.Context, email string) (response.LoginRes, int, error) {
	accessToken, payload, err := a.JwtMaker.CreateAccessToken(email, global.CUSTOMER_ROLE)
	if err != nil {
		return response.LoginRes{}, http.StatusInternalServerError, fmt.Errorf("an error occur when creating jwt access token: %v", err)
	}
	refreshToken, _, err := a.JwtMaker.CreateRefreshToken(email, global.CUSTOMER_ROLE)
	if err != nil {
		return response.LoginRes{}, http.StatusInternalServerError, fmt.Errorf("an error occur when creating jwt refrest token: %v", err)
	}

	return response.LoginRes{
		AccessToken:   accessToken,
		AccessPayload: payload,
		RefreshToken:  refreshToken,
	}, http.StatusOK, nil
}
