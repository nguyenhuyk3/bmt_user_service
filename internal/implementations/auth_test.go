package implementations

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"user_service/db/sqlc"
	"user_service/dto/request"
	fortests "user_service/for_tests"
	"user_service/global"
	"user_service/internal/mocks"
	"user_service/internal/services"
	"user_service/utils/cryptor"
	"user_service/utils/generator"
	"user_service/utils/token/jwt"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func newTestAuthService(t *testing.T, sqlStore sqlc.IStore,
	redisClient services.IRedis, messageBroker services.IMessageBroker) services.IAuth {
	fortests.LoadConfigsForTests()
	sercetKey, err := generator.GenerateStringNumberBasedOnLength(32)
	require.NoError(t, err)

	jwtMaker, err := jwt.NewJWTMaker(sercetKey)
	require.NoError(t, err)

	return NewAuthService(sqlStore, jwtMaker, redisClient, messageBroker)
}

func TestSendRegistrationOtp(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockSqlStore := mocks.NewMockIStore(ctrl)
	mockRedis := mocks.NewMockIRedis(ctrl)
	mockBroker := mocks.NewMockIMessageBroker(ctrl)
	authService := newTestAuthService(t, mockSqlStore, mockRedis, mockBroker)

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
			name: "email is in registration status",
			setUp: func() {
				mockRedis.EXPECT().ExistsKey(registrationOtpKey).Times(1).Return(true)
			},
			expectedStatus: http.StatusConflict,
			expectErr:      true,
		},
		{
			name: "email is in complete registration process",
			setUp: func() {
				mockRedis.EXPECT().ExistsKey(registrationOtpKey).Times(1).Return(false)
				mockRedis.EXPECT().ExistsKey(completeRegistrationProcessKey).Times(1).Return(true)
			},
			expectedStatus: http.StatusConflict,
			expectErr:      true,
		},
		{
			name: "failed to check email existence in database",
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
			name: "email already exists",
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
			name: "failed to send OTP to Kafka",
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
			name: "Success case",
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
