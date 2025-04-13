package implementations

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
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
	"github.com/stretchr/testify/require"
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

func TestSendRegistrationOtp(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockJwt := mocks.NewMockIMaker(ctrl)
	mockSqlStore := mocks.NewMockIStore(ctrl)
	mockRedis := mocks.NewMockIRedis(ctrl)
	mockBroker := mocks.NewMockIMessageBroker(ctrl)
	authService := newTestAuthService(mockJwt, mockSqlStore, mockRedis, mockBroker)

	email := "test@example.com"
	encryptedAesEmail, err := cryptor.AesEncrypt(email)
	require.NoError(t, err)

	registrationOtpKey := fmt.Sprintf("%s%s", global.REDIS_REGISTRATION_OTP_KEY, encryptedAesEmail)
	completeRegistrationProcessKey := fmt.Sprintf("%s%s", global.REDIS_COMPLETE_REGISTRATION_PROCESS, encryptedAesEmail)

	testCases := []struct {
		name           string
		setUp          func()
		expectedStatus int
		expectErr      bool
	}{
		{
			name: "Should return 409 when email is already in registration status",
			setUp: func() {
				mockRedis.EXPECT().ExistsKey(registrationOtpKey).Times(1).Return(true)
			},
			expectedStatus: http.StatusConflict,
			expectErr:      true,
		},
		{
			name: "Should return 409 when other person send registration otp request for the same mail",
			setUp: func() {
				mockRedis.EXPECT().ExistsKey(registrationOtpKey).Times(1).Return(false)
				mockRedis.EXPECT().ExistsKey(completeRegistrationProcessKey).Times(1).Return(true)
			},
			expectedStatus: http.StatusConflict,
			expectErr:      true,
		},
		{
			name: "Should return 500 when database email check fails",
			setUp: func() {
				mockRedis.EXPECT().ExistsKey(registrationOtpKey).Times(1).Return(false)
				mockRedis.EXPECT().ExistsKey(completeRegistrationProcessKey).Times(1).Return(false)
				mockSqlStore.EXPECT().
					CheckAccountExistsByEmail(gomock.Any(), email).
					Return(false, errors.New("failed to check email existence in database"))
			},
			expectedStatus: http.StatusInternalServerError,
			expectErr:      true,
		},
		{
			name: "Should return 409 when email already exists in database",
			setUp: func() {
				mockRedis.EXPECT().ExistsKey(registrationOtpKey).Times(1).Return(false)
				mockRedis.EXPECT().ExistsKey(completeRegistrationProcessKey).Times(1).Return(false)
				mockSqlStore.EXPECT().
					CheckAccountExistsByEmail(gomock.Any(), email).
					Return(true, nil)
			},
			expectedStatus: http.StatusConflict,
			expectErr:      true,
		},
		{
			name: "Should return 500 when OTP message sending to Kafka fails",
			setUp: func() {
				mockRedis.EXPECT().ExistsKey(registrationOtpKey).Times(1).Return(false)
				mockRedis.EXPECT().ExistsKey(completeRegistrationProcessKey).Times(1).Return(false)
				mockSqlStore.EXPECT().
					CheckAccountExistsByEmail(gomock.Any(), email).
					Return(false, nil)
				mockRedis.EXPECT().
					Save(registrationOtpKey, gomock.Any(), int64(ten_minutes)).
					Return(nil)
				mockBroker.EXPECT().
					SendMessage(global.REGISTRATION_OTP_EMAIL_TOPIC, email, gomock.Any()).
					Return(errors.New("send message to fafka failed"))
				mockRedis.EXPECT().Delete(registrationOtpKey).Return(nil)
			},
			expectedStatus: http.StatusInternalServerError,
			expectErr:      true,
		},
		{
			name: "Success case and return 200",
			setUp: func() {
				mockRedis.EXPECT().ExistsKey(registrationOtpKey).Times(1).Return(false)
				mockRedis.EXPECT().ExistsKey(completeRegistrationProcessKey).Times(1).Return(false)
				mockSqlStore.EXPECT().
					CheckAccountExistsByEmail(gomock.Any(), email).
					Return(false, nil)
				mockRedis.EXPECT().Save(registrationOtpKey, gomock.Any(), int64(ten_minutes)).Return(nil)
				mockBroker.EXPECT().
					SendMessage(global.REGISTRATION_OTP_EMAIL_TOPIC, email, gomock.Any()).
					Return(nil)
			},
			expectedStatus: http.StatusOK,
			expectErr:      false,
		},
	}

	for i := range testCases {
		tc := testCases[i]

		t.Run(tc.name, func(t *testing.T) {
			tc.setUp()

			status, err := authService.SendRegistrationOtp(context.TODO(), request.SendOtpReq{
				Email: email,
			})

			assert.Equal(t, tc.expectedStatus, status)
			if tc.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestVerifyRegistrationOtp(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockJwt := mocks.NewMockIMaker(ctrl)
	mockSqlStore := mocks.NewMockIStore(ctrl)
	mockRedis := mocks.NewMockIRedis(ctrl)
	mockBroker := mocks.NewMockIMessageBroker(ctrl)
	authService := newTestAuthService(mockJwt, mockSqlStore, mockRedis, mockBroker)

	email := "test@example.com"

	otp, err := generator.GenerateStringNumberBasedOnLength(6)
	require.NoError(t, err)

	encryptedAesEmail, err := cryptor.AesEncrypt(email)
	require.NoError(t, err)

	encryptedBcryptEmail, err := cryptor.BcryptHashInput(email)
	require.NoError(t, err)

	registrationOtpKey := fmt.Sprintf("%s%s", global.REDIS_REGISTRATION_OTP_KEY, encryptedAesEmail)
	completeRegistrationProcessKey := fmt.Sprintf("%s%s", global.REDIS_COMPLETE_REGISTRATION_PROCESS, encryptedAesEmail)
	// Define verifyOtp struct that matches the one in the implementation
	verifyOtpData := verifyOtp{
		EncryptedEmail: encryptedBcryptEmail,
		Otp:            otp,
	}

	testCases := []struct {
		name           string
		setUp          func()
		expectedStatus int
		expectErr      bool
	}{
		{
			name: "OTP has expired or not found",
			setUp: func() {
				mockRedis.EXPECT().
					Get(registrationOtpKey, gomock.Any()).
					// This won't actually set anything since we return an error
					SetArg(1, verifyOtpData).
					Return(errors.New("key not found"))
			},
			expectedStatus: http.StatusInternalServerError,
			expectErr:      true,
		},
		{
			name: "Invalid OTP",
			setUp: func() {
				mockRedis.EXPECT().
					Get(registrationOtpKey, gomock.Any()).
					SetArg(1, verifyOtp{
						EncryptedEmail: encryptedBcryptEmail,
						Otp:            "wrong-otp",
					}).
					Return(nil)
			},
			expectedStatus: http.StatusUnauthorized,
			expectErr:      true,
		},
		{
			name: "Invalid email",
			setUp: func() {
				// Create a different bcrypt hash for a different email
				wrongEmailHash, err := cryptor.BcryptHashInput("wrong-email@gmail.com")
				require.NoError(t, err)

				mockRedis.EXPECT().
					Get(registrationOtpKey, gomock.Any()).
					SetArg(1, verifyOtp{
						EncryptedEmail: wrongEmailHash,
						Otp:            otp,
					}).
					Return(nil)
			},
			expectedStatus: http.StatusUnauthorized,
			expectErr:      true,
		},
		{
			name: "Success case",
			setUp: func() {
				mockRedis.EXPECT().
					Get(registrationOtpKey, gomock.Any()).
					SetArg(1, verifyOtpData).
					Return(nil)
				mockRedis.EXPECT().
					Delete(registrationOtpKey).
					Return(nil)
				mockRedis.EXPECT().
					Save(completeRegistrationProcessKey,
						gomock.Any(), int64(ten_minutes)).
					Return(nil)
			},
			expectedStatus: http.StatusOK,
			expectErr:      false,
		},
	}

	for i := range testCases {
		tc := testCases[i]

		t.Run(tc.name, func(t *testing.T) {
			tc.setUp()

			status, err := authService.VerifyRegistrationOtp(context.TODO(), request.VerifyOtpReq{
				Email: email,
				Otp:   otp,
			})

			assert.Equal(t, tc.expectedStatus, status)
			if tc.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCompleteRegistration(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockJwt := mocks.NewMockIMaker(ctrl)
	mockSqlStore := mocks.NewMockIStore(ctrl)
	mockRedis := mocks.NewMockIRedis(ctrl)
	mockBroker := mocks.NewMockIMessageBroker(ctrl)
	authService := newTestAuthService(mockJwt, mockSqlStore, mockRedis, mockBroker)

	email := "test-email@gmail.com"

	otp, err := generator.GenerateStringNumberBasedOnLength(6)
	require.NoError(t, err)

	encryptedAesEmail, err := cryptor.AesEncrypt(email)
	require.NoError(t, err)
	// Encrypt email with bcrypt for testing
	encryptedBcryptEmail, err := cryptor.BcryptHashInput(email)
	require.NoError(t, err)

	completeRegistrationProcessKey := fmt.Sprintf("%s%s", global.REDIS_COMPLETE_REGISTRATION_PROCESS, encryptedAesEmail)
	// Sample registration request
	password, err := generator.GenerateStringNumberBasedOnLength(16)
	require.NoError(t, err)

	registrationReq := request.CompleteRegistrationReq{
		Account: request.Account{
			Email:    email,
			Password: password,
			Role:     global.CUSTOMER_ROLE,
		},
	}
	// Data stored in Redis
	verifyOtpData := verifyOtp{
		EncryptedEmail: encryptedBcryptEmail,
		Otp:            otp,
	}

	testCases := []struct {
		name           string
		setUp          func()
		expectedStatus int
		expectErr      bool
	}{
		{
			name: "Email not in complete registration process",
			setUp: func() {
				mockRedis.EXPECT().
					Get(completeRegistrationProcessKey, gomock.Any()).
					Return(errors.New("key not found"))
			},
			expectedStatus: http.StatusInternalServerError,
			expectErr:      true,
		},
		{
			name: "Encrypted email and email don't match",
			setUp: func() {
				// Create a different bcrypt hash for a different email
				wrongEmailHash, err := cryptor.BcryptHashInput("wrong-email@gmail.com")
				require.NoError(t, err)

				mockRedis.EXPECT().
					Get(completeRegistrationProcessKey, gomock.Any()).
					SetArg(1, verifyOtp{
						EncryptedEmail: wrongEmailHash,
						Otp:            otp,
					}).
					Return(nil)
			},
			expectedStatus: http.StatusBadRequest,
			expectErr:      true,
		},
		{
			name: "Failed to insert account",
			setUp: func() {
				mockRedis.EXPECT().
					Get(completeRegistrationProcessKey, gomock.Any()).
					SetArg(1, verifyOtpData).
					Return(nil)
				mockSqlStore.EXPECT().
					InsertAccountTran(gomock.Any(), gomock.Eq(registrationReq), false).
					Return(errors.New("database error"))
			},
			expectedStatus: http.StatusInternalServerError,
			expectErr:      true,
		},
		{
			name: "Success case",
			setUp: func() {
				mockRedis.EXPECT().
					Get(completeRegistrationProcessKey, gomock.Any()).
					SetArg(1, verifyOtpData).
					Return(nil)
				mockSqlStore.EXPECT().
					InsertAccountTran(gomock.Any(), gomock.Eq(registrationReq), false).
					Return(nil)
				mockRedis.EXPECT().
					Delete(completeRegistrationProcessKey).
					Return(nil)
			},
			expectedStatus: http.StatusCreated,
			expectErr:      false,
		},
	}

	for i := range testCases {
		tc := testCases[i]

		t.Run(tc.name, func(t *testing.T) {
			tc.setUp()

			status, err := authService.CompleteRegistration(context.TODO(), registrationReq)

			assert.Equal(t, tc.expectedStatus, status)
			if tc.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestLogin(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockJwt := mocks.NewMockIMaker(ctrl)
	mockSqlStore := mocks.NewMockIStore(ctrl)
	mockRedis := mocks.NewMockIRedis(ctrl)
	mockBroker := mocks.NewMockIMessageBroker(ctrl)
	authService := newTestAuthService(mockJwt, mockSqlStore, mockRedis, mockBroker)
	// email := "test-email@gmail.com"

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
					UpdateAction(gomock.Any(), gomock.Any()).
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
					UpdateAction(gomock.Any(), gomock.Any()).
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

			res, status, err := authService.Login(context.TODO(), tc.request)

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
