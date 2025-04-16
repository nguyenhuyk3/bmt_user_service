package implementations

import (
	"context"
	"errors"
	"fmt"
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
	"user_service/utils/cryptor"
	"user_service/utils/generator"
	"user_service/utils/token/jwt"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/redis/go-redis/v9"
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

func TestSendForgotPasswordOtp(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockJwt := mocks.NewMockIMaker(ctrl)
	mockSqlStore := mocks.NewMockIStore(ctrl)
	mockRedis := mocks.NewMockIRedis(ctrl)
	mockBroker := mocks.NewMockIMessageBroker(ctrl)
	authService := newTestAuthService(mockJwt, mockSqlStore, mockRedis, mockBroker)

	email := "test-email@gmail.com"
	aesEncryptedEmail, _ := cryptor.AesEncrypt(email)
	// bcryptEncryptedEmail, _ := cryptor.BcryptHashInput(email)

	// Keys for Redis
	attemptKey := fmt.Sprintf("%s%s", global.ATTEMPT_KEY, aesEncryptedEmail)
	blockKey := fmt.Sprintf("%s%s", global.BLOCK_FORGOT_PASSWORD_KEY, aesEncryptedEmail)
	forgotPasswordKey := fmt.Sprintf("%s%s", global.FORGOT_PASSWORD_KEY, aesEncryptedEmail)

	var res blockSendForgotPasswordOtp
	// otp, _ := generator.GenerateStringNumberBasedOnLength(6)

	testCases := []struct {
		name           string
		setUp          func()
		request        request.SendOtpReq
		expectedStatus int
		expectErr      bool
	}{
		{
			name: "Error checking email existence",
			setUp: func() {
				mockSqlStore.EXPECT().
					CheckAccountExistsByEmail(gomock.Any(), email).
					Return(false, errors.New("database error"))
			},
			request: request.SendOtpReq{
				Email: email,
			},
			expectedStatus: http.StatusInternalServerError,
			expectErr:      true,
		},
		{
			name: "Email doesn't exist",
			setUp: func() {
				mockSqlStore.EXPECT().
					CheckAccountExistsByEmail(gomock.Any(), email).
					Return(false, nil)
			},
			request: request.SendOtpReq{
				Email: email,
			},
			expectedStatus: http.StatusNotFound,
			expectErr:      true,
		},
		{
			name: "Account is blocked",
			setUp: func() {
				mockSqlStore.EXPECT().
					CheckAccountExistsByEmail(gomock.Any(), email).
					Return(true, nil)
				mockRedis.EXPECT().
					GetTTL(blockKey).
					Return(time.Hour, nil)
				mockRedis.EXPECT().
					Delete(attemptKey).
					Return(nil)
			},
			request: request.SendOtpReq{
				Email: email,
			},
			expectedStatus: http.StatusTooManyRequests,
			expectErr:      true,
		},
		{
			name: "First attempt - should succeed",
			setUp: func() {
				mockSqlStore.EXPECT().
					CheckAccountExistsByEmail(gomock.Any(), email).
					Return(true, nil)
				mockRedis.EXPECT().
					GetTTL(blockKey).
					Return(time.Duration(0), nil)
				mockRedis.EXPECT().
					Get(attemptKey, gomock.Any()).
					SetArg(1, res).
					Return(redis.Nil)
				mockRedis.EXPECT().
					Save(attemptKey, gomock.Any(), int64(three_hours)).
					Return(nil)
				mockRedis.EXPECT().
					GetTTL(forgotPasswordKey).
					Return(time.Duration(0), nil)
				mockBroker.EXPECT().
					SendMessage(
						gomock.Any(),
						global.FORGOT_PASSWORD_OTP_EMAIL_TOPIC,
						email,
						gomock.Any()).
					Return(nil)
				mockRedis.EXPECT().
					Save(forgotPasswordKey, gomock.Any(), int64(three_minutes)).
					Return(nil)
				mockRedis.EXPECT().
					Save(attemptKey, gomock.Any(), int64(three_hours)).
					Return(nil)
			},
			request: request.SendOtpReq{
				Email: email,
			},
			expectedStatus: http.StatusOK,
			expectErr:      false,
		},
		{
			name: "Too many attempts",
			setUp: func() {
				mockSqlStore.EXPECT().
					CheckAccountExistsByEmail(gomock.Any(), email).
					Return(true, nil)
				mockRedis.EXPECT().
					GetTTL(blockKey).
					Return(time.Duration(0), errors.New("key not found"))
				mockRedis.EXPECT().
					Get(attemptKey, gomock.Any()).
					DoAndReturn(func(_ string, v interface{}) error {
						blockData := v.(*blockSendForgotPasswordOtp)
						blockData.Count = 3

						return nil
					})
				mockRedis.EXPECT().
					Save(blockKey, gomock.Any(), int64(three_hours)).
					Return(nil)
				mockRedis.EXPECT().
					Delete(attemptKey).
					Return(nil)
			},
			request: request.SendOtpReq{
				Email: email,
			},
			expectedStatus: http.StatusTooManyRequests,
			expectErr:      true,
		},
		{
			name: "OTP already exists and not expired",
			setUp: func() {
				mockSqlStore.EXPECT().
					CheckAccountExistsByEmail(gomock.Any(), email).
					Return(true, nil)
				mockRedis.EXPECT().
					GetTTL(blockKey).
					Return(time.Duration(0), errors.New("key not found"))
				mockRedis.EXPECT().
					Get(attemptKey, gomock.Any()).
					Return(nil)
				mockRedis.EXPECT().
					GetTTL(forgotPasswordKey).
					Return(time.Minute, nil)
			},
			request: request.SendOtpReq{
				Email: email,
			},
			expectedStatus: http.StatusTooManyRequests,
			expectErr:      true,
		},
		{
			name: "Send email fails",
			setUp: func() {
				mockSqlStore.EXPECT().
					CheckAccountExistsByEmail(gomock.Any(), email).
					Return(true, nil)
				mockRedis.EXPECT().
					GetTTL(blockKey).
					Return(time.Duration(0), errors.New("key not found"))
				mockRedis.EXPECT().
					Get(attemptKey, gomock.Any()).
					Return(nil)
				mockRedis.EXPECT().
					GetTTL(forgotPasswordKey).
					Return(time.Duration(0), nil)
				mockBroker.EXPECT().
					SendMessage(
						gomock.Any(),
						global.FORGOT_PASSWORD_OTP_EMAIL_TOPIC,
						email,
						gomock.Any()).
					Return(errors.New("failed to send email"))
				mockRedis.EXPECT().
					Delete(attemptKey).
					Return(nil)
			},
			request: request.SendOtpReq{
				Email: email,
			},
			expectedStatus: http.StatusInternalServerError,
			expectErr:      true,
		},
	}

	for i := range testCases {
		tc := testCases[i]

		t.Run(tc.name, func(t *testing.T) {
			tc.setUp()

			status, err := authService.SendForgotPasswordOtp(context.TODO(), tc.request)

			assert.Equal(t, tc.expectedStatus, status)

			if tc.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestVerifyForgotPasswordOtp(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockJwt := mocks.NewMockIMaker(ctrl)
	mockSqlStore := mocks.NewMockIStore(ctrl)
	mockRedis := mocks.NewMockIRedis(ctrl)
	mockBroker := mocks.NewMockIMessageBroker(ctrl)
	authService := newTestAuthService(mockJwt, mockSqlStore, mockRedis, mockBroker)

	email := "test-email@gmail.com"
	otp, _ := generator.GenerateStringNumberBasedOnLength(6)

	// Generate encrypted email for testing
	aesEncryptedEmail, _ := cryptor.AesEncrypt(email)
	bcryptEncryptedEmail, _ := cryptor.BcryptHashInput(email)

	// Redis keys
	forgotPasswordKey := fmt.Sprintf("%s%s", global.FORGOT_PASSWORD_KEY, aesEncryptedEmail)
	completeProcessKey := fmt.Sprintf("%s%s", global.COMPLETE_FORGOT_PASSWORD_PROCESS, aesEncryptedEmail)

	testCases := []struct {
		name           string
		setUp          func()
		request        request.VerifyOtpReq
		expectedStatus int
		expectErr      bool
	}{
		{
			name: "Redis get error",
			setUp: func() {
				mockRedis.EXPECT().
					Get(forgotPasswordKey, gomock.Any()).
					Return(errors.New("redis error"))
			},
			request: request.VerifyOtpReq{
				Email: email,
				Otp:   otp,
			},
			expectedStatus: http.StatusInternalServerError,
			expectErr:      true,
		},
		{
			name: "OTP does not match",
			setUp: func() {
				mockRedis.EXPECT().
					Get(forgotPasswordKey, gomock.Any()).
					DoAndReturn(func(_ string, v interface{}) error {
						result := v.(*verifyOtp)
						result.EncryptedEmail = bcryptEncryptedEmail
						result.Otp = "654321" // Different OTP

						return nil
					})
			},
			request: request.VerifyOtpReq{
				Email: email,
				Otp:   otp,
			},
			expectedStatus: http.StatusUnauthorized,
			expectErr:      true,
		},
		{
			name: "Email does not match",
			setUp: func() {
				mockRedis.EXPECT().
					Get(forgotPasswordKey, gomock.Any()).
					DoAndReturn(func(_ string, v interface{}) error {
						result := v.(*verifyOtp)
						// A different hashed email that won't match when checking
						result.EncryptedEmail = "incorrect_hash"
						result.Otp = otp

						return nil
					})
			},
			request: request.VerifyOtpReq{
				Email: email,
				Otp:   otp,
			},
			expectedStatus: http.StatusUnauthorized,
			expectErr:      true,
		},
		{
			name: "OTP verification successful",
			setUp: func() {
				mockRedis.EXPECT().
					Get(forgotPasswordKey, gomock.Any()).
					DoAndReturn(func(_ string, v interface{}) error {
						result := v.(*verifyOtp)
						result.EncryptedEmail = bcryptEncryptedEmail
						result.Otp = otp

						return nil
					})
				mockRedis.EXPECT().
					Delete(forgotPasswordKey).
					Return(nil)
				mockRedis.EXPECT().
					Save(completeProcessKey, gomock.Any(), int64(ten_minutes)).
					Return(nil)
			},
			request: request.VerifyOtpReq{
				Email: email,
				Otp:   otp,
			},
			expectedStatus: http.StatusOK,
			expectErr:      false,
		},
	}

	for i := range testCases {
		tc := testCases[i]

		t.Run(tc.name, func(t *testing.T) {
			tc.setUp()

			status, err := authService.VerifyForgotPasswordOtp(context.TODO(), tc.request)

			assert.Equal(t, tc.expectedStatus, status)

			if tc.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCompleteForgotPassword(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockJwt := mocks.NewMockIMaker(ctrl)
	mockSqlStore := mocks.NewMockIStore(ctrl)
	mockRedis := mocks.NewMockIRedis(ctrl)
	mockBroker := mocks.NewMockIMessageBroker(ctrl)
	authService := newTestAuthService(mockJwt, mockSqlStore, mockRedis, mockBroker)

	email := "test-email@gmail.com"
	newPassword := "NewSecurePassword123!"
	aesEncryptedEmail, _ := cryptor.AesEncrypt(email)
	bcryptEncryptedEmail, _ := cryptor.BcryptHashInput(email)
	completeProcessKey := fmt.Sprintf("%s%s", global.COMPLETE_FORGOT_PASSWORD_PROCESS, aesEncryptedEmail)
	attemptKey := fmt.Sprintf("%s%s", global.ATTEMPT_KEY, aesEncryptedEmail)

	testCases := []struct {
		name           string
		setUp          func()
		request        request.CompleteForgotPasswordReq
		expectedStatus int
		expectErr      bool
	}{
		{
			name: "Key does not exist in Redis",
			setUp: func() {
				mockRedis.EXPECT().
					ExistsKey(completeProcessKey).
					Return(false)
			},
			request: request.CompleteForgotPasswordReq{
				Email:       email,
				NewPassword: newPassword,
			},
			expectedStatus: http.StatusConflict,
			expectErr:      true,
		},
		{
			name: "Redis get error",
			setUp: func() {
				mockRedis.EXPECT().
					ExistsKey(completeProcessKey).
					Return(true)
				mockRedis.EXPECT().
					Get(completeProcessKey, gomock.Any()).
					Return(errors.New("redis error"))
			},
			request: request.CompleteForgotPasswordReq{
				Email:       email,
				NewPassword: newPassword,
			},
			expectedStatus: http.StatusInternalServerError,
			expectErr:      true,
		},
		{
			name: "Email mismatch",
			setUp: func() {
				mockRedis.EXPECT().
					ExistsKey(completeProcessKey).
					Return(true)
				mockRedis.EXPECT().
					Get(completeProcessKey, gomock.Any()).
					DoAndReturn(func(_ string, v interface{}) error {
						result := v.(*verifyOtp)
						// A different hashed email that won't match when checking
						result.EncryptedEmail = "incorrect_hash"
						return nil
					})
			},
			request: request.CompleteForgotPasswordReq{
				Email:       email,
				NewPassword: newPassword,
			},
			expectedStatus: http.StatusUnauthorized,
			expectErr:      true,
		},
		{
			name: "SQL update password error",
			setUp: func() {
				mockRedis.EXPECT().
					ExistsKey(completeProcessKey).
					Return(true)
				mockRedis.EXPECT().
					Get(completeProcessKey, gomock.Any()).
					DoAndReturn(func(_ string, v interface{}) error {
						result := v.(*verifyOtp)
						result.EncryptedEmail = bcryptEncryptedEmail
						return nil
					})
				mockSqlStore.EXPECT().
					UpdatePassword(gomock.Any(), gomock.Any()).
					Return(errors.New("database error"))
			},
			request: request.CompleteForgotPasswordReq{
				Email:       email,
				NewPassword: newPassword,
			},
			expectedStatus: http.StatusInternalServerError,
			expectErr:      true,
		},
		{
			name: "Password reset successful",
			setUp: func() {
				mockRedis.EXPECT().
					ExistsKey(completeProcessKey).
					Return(true)
				mockRedis.EXPECT().
					Get(completeProcessKey, gomock.Any()).
					DoAndReturn(func(_ string, v interface{}) error {
						result := v.(*verifyOtp)
						result.EncryptedEmail = bcryptEncryptedEmail
						return nil
					})
				mockSqlStore.EXPECT().
					UpdatePassword(gomock.Any(), gomock.Any()).
					DoAndReturn(func(_ context.Context, params sqlc.UpdatePasswordParams) error {
						assert.Equal(t, email, params.Email)
						// Check that the password is hashed
						assert.NotEqual(t, newPassword, params.Password)
						return nil
					})
				mockRedis.EXPECT().
					Delete(attemptKey).
					Return(nil)
				mockRedis.EXPECT().
					Delete(completeProcessKey).
					Return(nil)
			},
			request: request.CompleteForgotPasswordReq{
				Email:       email,
				NewPassword: newPassword,
			},
			expectedStatus: http.StatusOK,
			expectErr:      false,
		},
	}

	for i := range testCases {
		tc := testCases[i]

		t.Run(tc.name, func(t *testing.T) {
			tc.setUp()

			status, err := authService.CompleteForgotPassword(context.TODO(), tc.request)

			assert.Equal(t, tc.expectedStatus, status)

			if tc.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
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
