package login

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"time"
	"user_service/db/sqlc"
	"user_service/dto/request"
	"user_service/dto/response"
	"user_service/internal/services"
	"user_service/utils/cryptor"
	"user_service/utils/token/jwt"

	"github.com/jackc/pgx/v5/pgtype"
)

type loginService struct {
	SqlStore sqlc.IStore
	JwtMaker jwt.IMaker
}

// Login implements services.ILogin.
func (l *loginService) Login(ctx context.Context, arg request.LoginReq) (response.LoginRes, int, error) {
	var result response.LoginRes

	user, err := l.SqlStore.GetUserByEmail(ctx, arg.Email)
	if err != nil {
		if err == sql.ErrNoRows {
			return response.LoginRes{}, http.StatusNotFound, errors.New("user not found")
		}

		return response.LoginRes{}, http.StatusInternalServerError, fmt.Errorf("failed to fetch user: %w", err)
	}

	isMatch := cryptor.BcryptCheckInput(user.Password, arg.Password)
	if isMatch != nil {
		return response.LoginRes{}, http.StatusUnauthorized, errors.New("password does not match")
	}

	accessToken, accessPayload, err := l.JwtMaker.CreateAccessToken(user.Email, string(user.Role.Roles))
	if err != nil {
		return response.LoginRes{}, http.StatusInternalServerError, fmt.Errorf("failed to create access token: %w", err)
	}
	result.AccessToken = accessToken
	result.AccessPayload = accessPayload

	refreshToken, _, err := l.JwtMaker.CreateRefreshToken(user.Email, string(user.Role.Roles))
	if err != nil {
		return response.LoginRes{}, http.StatusInternalServerError, fmt.Errorf("failed to create refresh token: %w", err)
	}
	result.RefreshToken = refreshToken

	_, err = l.SqlStore.UpdateAction(ctx, sqlc.UpdateActionParams{
		Email: user.Email,
		LoginAt: pgtype.Timestamptz{
			Time:  time.Now(),
			Valid: true,
		},
		LogoutAt: pgtype.Timestamptz{
			Valid: false,
		},
	})
	if err != nil {
		return response.LoginRes{}, http.StatusInternalServerError, fmt.Errorf("failed to update user action: %w", err)
	}

	return result, http.StatusOK, nil
}

func NewLoginService(
	sqlStore sqlc.IStore,
	jwtMaker jwt.IMaker,
) services.ILogin {
	return &loginService{
		SqlStore: sqlStore,
		JwtMaker: jwtMaker,
	}
}
