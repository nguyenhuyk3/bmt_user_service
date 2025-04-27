package registration

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"user_service/db/sqlc"
	"user_service/dto/request"
	"user_service/global"
	"user_service/internal/mocks"
	"user_service/internal/services"
	"user_service/utils/cryptor"
	"user_service/utils/generator"

	fortests "user_service/for_tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func newTestAuthService(
	sqlStore sqlc.IStore,
	redisClient services.IRedis,
	messageBroker services.IMessageBrokerWriter) services.IRegistration {
	fortests.LoadConfigsForTests()

	return NewRegistrationService(sqlStore, redisClient, messageBroker)
}

func TestSendRegistrationOtp(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockSqlStore := mocks.NewMockIStore(ctrl)
	mockRedis := mocks.NewMockIRedis(ctrl)
	mockBroker := mocks.NewMockIMessageBrokerWriter(ctrl)
	service := newTestAuthService(mockSqlStore, mockRedis, mockBroker)

	email := "test-email@gmail.com"
	arg := sqlc.CheckAccountExistsByEmailAndSourceParams{
		Email: email,
		Source: sqlc.NullSources{
			Sources: sqlc.SourcesApp,
			Valid:   true},
	}
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
					CheckAccountExistsByEmailAndSource(gomock.Any(), arg).
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
					CheckAccountExistsByEmailAndSource(gomock.Any(), arg).
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
					CheckAccountExistsByEmailAndSource(gomock.Any(), arg).
					Return(false, nil)
				mockRedis.EXPECT().
					Save(registrationOtpKey, gomock.Any(), int64(ten_minutes)).
					Return(nil)
				mockBroker.EXPECT().
					SendMessage(gomock.Any(), global.REGISTRATION_OTP_EMAIL_TOPIC, email, gomock.Any()).
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
					CheckAccountExistsByEmailAndSource(gomock.Any(), arg).
					Return(false, nil)
				mockRedis.EXPECT().Save(registrationOtpKey, gomock.Any(), int64(ten_minutes)).Return(nil)
				mockBroker.EXPECT().
					SendMessage(gomock.Any(), global.REGISTRATION_OTP_EMAIL_TOPIC, email, gomock.Any()).
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

			status, err := service.SendRegistrationOtp(context.TODO(), request.SendOtpReq{
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

	mockSqlStore := mocks.NewMockIStore(ctrl)
	mockRedis := mocks.NewMockIRedis(ctrl)
	mockBroker := mocks.NewMockIMessageBrokerWriter(ctrl)
	service := newTestAuthService(mockSqlStore, mockRedis, mockBroker)

	email := "test-email@gmail.com"

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

			status, err := service.VerifyRegistrationOtp(context.TODO(), request.VerifyOtpReq{
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

	mockSqlStore := mocks.NewMockIStore(ctrl)
	mockRedis := mocks.NewMockIRedis(ctrl)
	mockBroker := mocks.NewMockIMessageBrokerWriter(ctrl)
	service := newTestAuthService(mockSqlStore, mockRedis, mockBroker)

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

			status, err := service.CompleteRegistration(context.TODO(), registrationReq)

			assert.Equal(t, tc.expectedStatus, status)
			if tc.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
