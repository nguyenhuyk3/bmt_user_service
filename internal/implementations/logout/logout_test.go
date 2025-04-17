package logout

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"user_service/db/sqlc"
	"user_service/internal/mocks"
	"user_service/internal/services"

	fortests "user_service/for_tests"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func newLogoutService(
	sqlStore sqlc.IStore,
) services.ILogout {
	fortests.LoadConfigsForTests()

	return NewLogoutService(sqlStore)
}

func TestLogout(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockSqlStore := mocks.NewMockIStore(ctrl)
	logoutService := newLogoutService(mockSqlStore)

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
					UpdateUserAction(gomock.Any(), gomock.Any()).
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
					UpdateUserAction(gomock.Any(), gomock.Any()).
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

			status, err := logoutService.Logout(context.TODO(), tc.email)

			assert.Equal(t, tc.expectedStatus, status)

			if tc.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
