package login

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"testing"
	"user_service/db/sqlc"
	"user_service/dto/request"
	"user_service/dto/response"
	"user_service/internal/mocks"
	"user_service/internal/services"
	"user_service/utils/cryptor"
	"user_service/utils/generator"
	"user_service/utils/token/jwt"

	fortests "user_service/for_tests"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func newTestLoginService(
	jwtMaker jwt.IMaker,
	sqlStore sqlc.IStore,
) services.ILogin {
	fortests.LoadConfigsForTests()

	return NewLoginService(sqlStore, jwtMaker)
}

func TestLogin(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockJwt := mocks.NewMockIMaker(ctrl)
	mockSqlStore := mocks.NewMockIStore(ctrl)

	loginService := newTestLoginService(mockJwt, mockSqlStore)

	password, err := generator.GenerateStringNumberBasedOnLength(18)
	require.NoError(t, err)

	hashedPassword, err := cryptor.BcryptHashInput(password)
	require.NoError(t, err)

	accessToken, err := generator.GenerateStringNumberBasedOnLength(64)
	require.NoError(t, err)

	refreshToken, err := generator.GenerateStringNumberBasedOnLength(64)
	require.NoError(t, err)

	email := "test-email@gmail.com"
	user := request.LoginReq{
		Email:    email,
		Password: password,
	}

	testCases := []struct {
		name             string
		setUp            func()
		request          request.LoginReq
		expectedResponse response.LoginRes
		expectedStatus   int
		expectErr        bool
	}{
		{
			name: "User not found",
			setUp: func() {
				mockSqlStore.EXPECT().
					GetUserByEmail(gomock.Any(), email).
					Return(sqlc.Accounts{}, sql.ErrNoRows)
			},
			request:          user,
			expectedResponse: response.LoginRes{},
			expectedStatus:   http.StatusNotFound,
			expectErr:        true,
		},
		{
			name: "Database error when fetching user",
			setUp: func() {
				mockSqlStore.EXPECT().
					GetUserByEmail(gomock.Any(), email).
					Return(sqlc.Accounts{}, errors.New("database connection error"))
			},
			request:          user,
			expectedResponse: response.LoginRes{},
			expectedStatus:   http.StatusInternalServerError,
			expectErr:        true,
		},
		{
			name: "Password does not match",
			setUp: func() {
				mockSqlStore.EXPECT().
					GetUserByEmail(gomock.Any(), email).
					Return(sqlc.Accounts{
						Password: "wrong-hashed-password",
					}, nil)
			},
			request:          user,
			expectedResponse: response.LoginRes{},
			expectedStatus:   http.StatusUnauthorized,
			expectErr:        true,
		},
		{
			name: "Error creating access token",
			setUp: func() {
				mockSqlStore.EXPECT().
					GetUserByEmail(gomock.Any(), email).
					Return(sqlc.Accounts{
						Email:    email,
						Password: hashedPassword,
					}, nil)
				mockJwt.EXPECT().
					CreateAccessToken(gomock.Any(), gomock.Any()).
					Return("", &jwt.Payload{}, errors.New("failed to create access token"))
			},
			request:          user,
			expectedResponse: response.LoginRes{},
			expectedStatus:   http.StatusInternalServerError,
			expectErr:        true,
		},
		{
			name: "Error creating refresh token",
			setUp: func() {
				mockSqlStore.EXPECT().
					GetUserByEmail(gomock.Any(), email).
					Return(sqlc.Accounts{
						Email:    email,
						Password: hashedPassword,
						Role:     sqlc.NullRoles{Roles: sqlc.RolesCustomer, Valid: true},
					}, nil)
				mockJwt.EXPECT().
					CreateAccessToken(gomock.Any(), gomock.Any()).
					Return(accessToken, &jwt.Payload{}, nil)
				mockJwt.EXPECT().
					CreateRefreshToken(gomock.Any(), gomock.Any()).
					Return("", &jwt.Payload{}, errors.New("failed to create refresh token"))
			},
			request:          user,
			expectedResponse: response.LoginRes{},
			expectedStatus:   http.StatusInternalServerError,
			expectErr:        true,
		},
		{
			name: "Update user action failed",
			setUp: func() {
				mockSqlStore.EXPECT().
					GetUserByEmail(gomock.Any(), email).
					Return(sqlc.Accounts{
						Email:    email,
						Password: hashedPassword,
						Role:     sqlc.NullRoles{Roles: sqlc.RolesCustomer, Valid: true},
					}, nil)
				mockJwt.EXPECT().
					CreateAccessToken(gomock.Any(), gomock.Any()).
					Return(accessToken, &jwt.Payload{}, nil)
				mockJwt.EXPECT().
					CreateRefreshToken(gomock.Any(), gomock.Any()).
					Return(refreshToken, &jwt.Payload{}, nil)
				mockSqlStore.EXPECT().
					UpdateUserAction(gomock.Any(), gomock.Any()).
					Return(pgconn.CommandTag{}, errors.New("update user action failed"))
			},
			request:          user,
			expectedResponse: response.LoginRes{},
			expectedStatus:   http.StatusInternalServerError,
			expectErr:        true,
		},
		{
			name: "Success",
			setUp: func() {
				mockSqlStore.EXPECT().
					GetUserByEmail(gomock.Any(), email).
					Return(sqlc.Accounts{
						Email:    email,
						Password: hashedPassword,
						Role:     sqlc.NullRoles{Roles: sqlc.RolesCustomer, Valid: true},
					}, nil)
				mockJwt.EXPECT().
					CreateAccessToken(gomock.Any(), gomock.Any()).
					Return(accessToken, &jwt.Payload{}, nil)
				mockJwt.EXPECT().
					CreateRefreshToken(gomock.Any(), gomock.Any()).
					Return(refreshToken, &jwt.Payload{}, nil)
				mockSqlStore.EXPECT().
					UpdateUserAction(gomock.Any(), gomock.Any()).
					Return(pgconn.CommandTag{}, nil)
			},
			request: user,
			expectedResponse: response.LoginRes{
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			},
			expectedStatus: http.StatusOK,
			expectErr:      false,
		},
	}

	for i := range testCases {
		tc := testCases[i]

		t.Run(tc.name, func(t *testing.T) {
			tc.setUp()

			res, status, err := loginService.Login(context.TODO(), tc.request)

			assert.Equal(t, tc.expectedStatus, status)

			if tc.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedResponse.AccessToken, res.AccessToken)
				assert.Equal(t, tc.expectedResponse.RefreshToken, res.RefreshToken)
				// You can add more assertions for the payload if needed
			}
		})
	}
}

func TestCreateNewAccessToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockJwt := mocks.NewMockIMaker(ctrl)
	mockSqlStore := mocks.NewMockIStore(ctrl)
	loginService := newTestLoginService(mockJwt, mockSqlStore)
	// Generate a sample refresh token
	refreshToken, err := generator.GenerateStringNumberBasedOnLength(64)
	require.NoError(t, err)
	// Generate a sample access token
	accessToken, err := generator.GenerateStringNumberBasedOnLength(64)
	require.NoError(t, err)
	// Prepare test payload
	testPayload := &jwt.Payload{
		Email: "test-email@gmail.com",
		Role:  string(sqlc.RolesCustomer),
	}

	testCases := []struct {
		name            string
		setUp           func()
		refreshToken    string
		expectedToken   string
		expectedPayload interface{}
		expectedStatus  int
		expectErr       bool
	}{
		{
			name: "Success",
			setUp: func() {
				mockJwt.EXPECT().
					RefreshAccessToken(refreshToken).
					Return(accessToken, testPayload, nil)
			},
			refreshToken:    refreshToken,
			expectedToken:   accessToken,
			expectedPayload: testPayload,
			expectedStatus:  http.StatusOK,
			expectErr:       false,
		},
		// {
		// 	name: "Invalid refresh token",
		// 	setUp: func() {
		// 		mockJwt.EXPECT().
		// 			RefreshAccessToken(refreshToken).
		// 			Return("", nil, errors.New("invalid or expired refresh token"))
		// 	},
		// 	refreshToken:    refreshToken,
		// 	expectedToken:   "",
		// 	expectedPayload: nil,
		// 	expectedStatus:  http.StatusInternalServerError,
		// 	expectErr:       true,
		// },
		{
			name: "Token generation error",
			setUp: func() {
				mockJwt.EXPECT().
					RefreshAccessToken(refreshToken).
					Return("", nil, errors.New("failed to generate new access token"))
			},
			refreshToken:    refreshToken,
			expectedToken:   "",
			expectedPayload: nil,
			expectedStatus:  http.StatusInternalServerError,
			expectErr:       true,
		},
		// {
		// 	name: "Empty refresh token",
		// 	setUp: func() {
		// 		mockJwt.EXPECT().
		// 			RefreshAccessToken("").
		// 			Return("", nil, errors.New("refresh token cannot be empty"))
		// 	},
		// 	refreshToken:    "",
		// 	expectedToken:   "",
		// 	expectedPayload: nil,
		// 	expectedStatus:  http.StatusInternalServerError,
		// 	expectErr:       true,
		// },
	}

	for i := range testCases {
		tc := testCases[i]

		t.Run(tc.name, func(t *testing.T) {
			tc.setUp()

			token, payload, status, err := loginService.CreateNewAccessToken(context.TODO(), tc.refreshToken)

			assert.Equal(t, tc.expectedStatus, status)

			if tc.expectErr {
				assert.Error(t, err)
				assert.Empty(t, token)
				assert.Nil(t, payload)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedToken, token)
				assert.Equal(t, tc.expectedPayload, payload)
			}
		})
	}
}
