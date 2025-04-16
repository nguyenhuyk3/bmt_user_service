package implementations

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
	"user_service/db/sqlc"
	"user_service/dto/request"
	"user_service/dto/response"
	fortests "user_service/for_tests"
	"user_service/global"
	"user_service/internal/mocks"
	"user_service/internal/services"
	"user_service/utils/token/jwt"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func newTestAuthService(
	jwtMaker jwt.IMaker,
	sqlStore sqlc.IStore,
	redisClient services.IRedis,
	messageBroker services.IMessageBroker) services.IAuth {
	fortests.LoadConfigsForTests()

	return NewAuthService(sqlStore, jwtMaker, redisClient, messageBroker)
}

func TestLogout(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockJwt := mocks.NewMockIMaker(ctrl)
	mockSqlStore := mocks.NewMockIStore(ctrl)
	mockRedis := mocks.NewMockIRedis(ctrl)
	mockBroker := mocks.NewMockIMessageBroker(ctrl)
	authService := newTestAuthService(mockJwt, mockSqlStore, mockRedis, mockBroker)

	email := "test-email@gmail.com"

	testCases := []struct {
		name           string
		setUp          func()
		email          string
		expectedStatus int
		expectErr      bool
	}{
		{
			name: "Database error",
			setUp: func() {
				mockSqlStore.EXPECT().
					UpdateAction(gomock.Any(), gomock.Any()).
					Return(pgconn.CommandTag{}, errors.New("database error"))
			},
			email:          email,
			expectedStatus: http.StatusInternalServerError,
			expectErr:      true,
		},
		{
			name: "Successful logout",
			setUp: func() {
				mockSqlStore.EXPECT().
					UpdateAction(gomock.Any(), gomock.Any()).
					Return(pgconn.CommandTag{}, nil)
			},
			email:          email,
			expectedStatus: http.StatusOK,
			expectErr:      false,
		},
	}

	for i := range testCases {
		tc := testCases[i]

		t.Run(tc.name, func(t *testing.T) {
			tc.setUp()

			status, err := authService.Logout(context.TODO(), tc.email)

			assert.Equal(t, tc.expectedStatus, status)

			if tc.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestInsertGoogleUser(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockJwt := mocks.NewMockIMaker(ctrl)
	mockSqlStore := mocks.NewMockIStore(ctrl)
	mockRedis := mocks.NewMockIRedis(ctrl)
	mockBroker := mocks.NewMockIMessageBroker(ctrl)
	authService := newTestAuthService(mockJwt, mockSqlStore, mockRedis, mockBroker)

	googleUserInfo := response.OAuth2UserInfo{
		Id:    "123456789",
		Email: "google-user@gmail.com",
		Name:  "Google User",
	}

	testCases := []struct {
		name           string
		setUp          func()
		userInfo       response.OAuth2UserInfo
		expectedStatus int
		expectErr      bool
	}{
		{
			name: "Database error",
			setUp: func() {
				mockSqlStore.EXPECT().
					InsertAccountTran(gomock.Any(), gomock.Any(), true).
					Return(errors.New("database error"))
			},
			userInfo:       googleUserInfo,
			expectedStatus: http.StatusInternalServerError,
			expectErr:      true,
		},
		{
			name: "Successful Google user insertion",
			setUp: func() {
				mockSqlStore.EXPECT().
					InsertAccountTran(gomock.Any(), gomock.Any(), true).
					DoAndReturn(func(_ context.Context, req request.CompleteRegistrationReq, _ bool) error {
						assert.Equal(t, googleUserInfo.Email, req.Account.Email)
						assert.Equal(t, global.CUSTOMER_ROLE, req.Account.Role)
						assert.Equal(t, googleUserInfo.Name, req.Info.Name)
						assert.Equal(t, global.MALE, req.Info.Sex)
						assert.Equal(t, "", req.Info.BirthDay)

						// Verify password is hashed
						assert.NotEqual(t, googleUserInfo.Id, req.Account.Password)

						return nil
					})
			},
			userInfo:       googleUserInfo,
			expectedStatus: http.StatusOK,
			expectErr:      false,
		},
	}

	for i := range testCases {
		tc := testCases[i]

		t.Run(tc.name, func(t *testing.T) {
			tc.setUp()

			status, err := authService.InserOAuth2UsertUser(context.TODO(), tc.userInfo)

			assert.Equal(t, tc.expectedStatus, status)

			if tc.expectErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "an error occur when insert to db")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCheckGoogleUserByEmail(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockJwt := mocks.NewMockIMaker(ctrl)
	mockSqlStore := mocks.NewMockIStore(ctrl)
	mockRedis := mocks.NewMockIRedis(ctrl)
	mockBroker := mocks.NewMockIMessageBroker(ctrl)
	authService := newTestAuthService(mockJwt, mockSqlStore, mockRedis, mockBroker)

	email := "test-email@gmail.com"

	testCases := []struct {
		name          string
		setUp         func()
		email         string
		expectedExist bool
		expectErr     bool
	}{
		{
			name: "Database error",
			setUp: func() {
				mockSqlStore.EXPECT().
					CheckAccountExistsByEmail(gomock.Any(), email).
					Return(false, errors.New("database error"))
			},
			email:         email,
			expectedExist: false,
			expectErr:     true,
		},
		{
			name: "Email already exists",
			setUp: func() {
				mockSqlStore.EXPECT().
					CheckAccountExistsByEmail(gomock.Any(), email).
					Return(true, nil)
			},
			email:         email,
			expectedExist: true,
			expectErr:     true,
		},
		{
			name: "Email does not exist",
			setUp: func() {
				mockSqlStore.EXPECT().
					CheckAccountExistsByEmail(gomock.Any(), email).
					Return(false, nil)
			},
			email:         email,
			expectedExist: false,
			expectErr:     false,
		},
	}

	for i := range testCases {
		tc := testCases[i]

		t.Run(tc.name, func(t *testing.T) {
			tc.setUp()

			exists, err := authService.CheckOAuth2UserByEmail(context.TODO(), tc.email)

			assert.Equal(t, tc.expectedExist, exists)

			if tc.expectErr {
				assert.Error(t, err)
				if tc.expectedExist {
					assert.Contains(t, err.Error(), "this email has been registered")
				} else {
					assert.Contains(t, err.Error(), "an error occur when querying to db")
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestReturnToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockJwt := mocks.NewMockIMaker(ctrl)
	mockSqlStore := mocks.NewMockIStore(ctrl)
	mockRedis := mocks.NewMockIRedis(ctrl)
	mockBroker := mocks.NewMockIMessageBroker(ctrl)
	authService := newTestAuthService(mockJwt, mockSqlStore, mockRedis, mockBroker)

	email := "test-email@gmail.com"
	accessToken := "mock-access-token"
	refreshToken := "mock-refresh-token"
	mockPayload := &jwt.Payload{
		Email:     email,
		Role:      global.CUSTOMER_ROLE,
		IssuedAt:  time.Now(),
		ExpiredAt: time.Now().Add(time.Hour),
	}

	testCases := []struct {
		name           string
		setUp          func()
		email          string
		expectedStatus int
		expectErr      bool
	}{
		{
			name: "Access token creation error",
			setUp: func() {
				mockJwt.EXPECT().
					CreateAccessToken(email, global.CUSTOMER_ROLE).
					Return("", nil, errors.New("token creation error"))
			},
			email:          email,
			expectedStatus: http.StatusInternalServerError,
			expectErr:      true,
		},
		{
			name: "Refresh token creation error",
			setUp: func() {
				mockJwt.EXPECT().
					CreateAccessToken(email, global.CUSTOMER_ROLE).
					Return(accessToken, mockPayload, nil)
				mockJwt.EXPECT().
					CreateRefreshToken(email, global.CUSTOMER_ROLE).
					Return("", nil, errors.New("refresh token creation error"))
			},
			email:          email,
			expectedStatus: http.StatusInternalServerError,
			expectErr:      true,
		},
		{
			name: "Successful token generation",
			setUp: func() {
				mockJwt.EXPECT().
					CreateAccessToken(email, global.CUSTOMER_ROLE).
					Return(accessToken, mockPayload, nil)
				mockJwt.EXPECT().
					CreateRefreshToken(email, global.CUSTOMER_ROLE).
					Return(refreshToken, mockPayload, nil)
			},
			email:          email,
			expectedStatus: http.StatusOK,
			expectErr:      false,
		},
	}

	for i := range testCases {
		tc := testCases[i]

		t.Run(tc.name, func(t *testing.T) {
			tc.setUp()

			loginRes, status, err := authService.ReturnToken(context.TODO(), tc.email)

			assert.Equal(t, tc.expectedStatus, status)

			if tc.expectErr {
				assert.Error(t, err)
				if strings.Contains(tc.name, "Access token") {
					assert.Contains(t, err.Error(), "an error occur when creating jwt access token")
				} else if strings.Contains(tc.name, "Refresh token") {
					assert.Contains(t, err.Error(), "an error occur when creating jwt refrest token")
				}
				assert.Equal(t, response.LoginRes{}, loginRes)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, accessToken, loginRes.AccessToken)
				assert.Equal(t, refreshToken, loginRes.RefreshToken)
				assert.Equal(t, mockPayload, loginRes.AccessPayload)
			}
		})
	}
}
