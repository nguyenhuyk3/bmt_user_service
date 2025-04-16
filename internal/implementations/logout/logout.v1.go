package logout

import (
	"context"
	"net/http"
	"time"
	"user_service/db/sqlc"
	"user_service/internal/services"

	"github.com/jackc/pgx/v5/pgtype"
)

type logoutService struct {
	SqlStore sqlc.IStore
}

func NewLogoutService(
	sqlStore sqlc.IStore,

) services.ILogout {
	return &logoutService{
		SqlStore: sqlStore,
	}
}

// Logout implements services.IAuth.
func (l *logoutService) Logout(ctx context.Context, email string) (int, error) {
	_, err := l.SqlStore.UpdateAction(ctx, sqlc.UpdateActionParams{
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
