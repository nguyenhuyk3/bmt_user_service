package sqlc

import (
	"context"
	"fmt"
	"time"
	"user_service/dto/request"
	"user_service/utils/cryptor"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type SqlStore struct {
	connPool *pgxpool.Pool
	*Queries
}

func (s *SqlStore) execTran(ctx context.Context, fn func(*Queries) error) error {
	// Start transaction
	tran, err := s.connPool.Begin(ctx)
	if err != nil {
		return err
	}

	q := New(tran)
	// fn performs a series of operations down the db
	err = fn(q)
	if err != nil {
		// If an error occurs, rollback the transaction
		if rbErr := tran.Rollback(ctx); rbErr != nil {
			return fmt.Errorf("tran err: %v, rollback err: %v", err, rbErr)
		}

		return err
	}

	return tran.Commit(ctx)
}

// InsertAccountTran implements IStore.
func (s *SqlStore) InsertAccountTran(ctx context.Context, arg request.CompleteRegistrationReq, isFromOAuth2 bool) error {
	err := s.execTran(ctx, func(q *Queries) error {
		var role NullRoles
		err := role.Scan(arg.Account.Role)
		if err != nil {
			return fmt.Errorf("failed to scan role: %v", err)
		}

		hashedPassword, _ := cryptor.BcryptHashInput(arg.Account.Password)
		err = q.InsertAccount(ctx, InsertAccountParams{
			Email:    arg.Account.Email,
			Password: hashedPassword,
			Source: NullSources{
				Sources: SourcesApp,
				Valid:   true},
			Role: role,
		})
		if err != nil {
			return fmt.Errorf("failed to insert account: %v", err)
		}

		var sex NullSex
		err = sex.Scan(arg.Info.Sex)
		if err != nil {
			return fmt.Errorf("failed to scan sex: %v", err)
		}

		err = q.InsertUserInfo(ctx, InsertUserInfoParams{
			Email: pgtype.Text{
				String: arg.Account.Email,
				Valid:  true,
			},
			Name:     arg.Info.Name,
			Sex:      sex,
			BirthDay: arg.Info.BirthDay,
		})
		if err != nil {
			return fmt.Errorf("failed to insert user info: %v", err)
		}

		if !isFromOAuth2 {
			err = q.InsertUserAction(ctx, pgtype.Text{
				String: arg.Account.Email,
				Valid:  true,
			})
			if err != nil {
				return fmt.Errorf("failed to insert user action: %v", err)
			}
		} else {
			err = q.InsertOAuth2Action(ctx, pgtype.Text{
				String: arg.Account.Email,
				Valid:  true,
			})
			if err != nil {
				return fmt.Errorf("failed to insert oauth2 user action: %v", err)
			}
		}

		return nil
	})

	if err != nil {
		// If the transaction failed, return the error
		return fmt.Errorf("transaction failed: %v", err)
	}

	return err
}

// UpdateUserInforTran implements IStore.
func (s *SqlStore) UpdateUserInforTran(ctx context.Context, arg request.ChangeInforReq) error {
	err := s.execTran(ctx, func(q *Queries) error {
		var sex NullSex
		err := sex.Scan(arg.Sex)
		if err != nil {
			return fmt.Errorf("failed to scan sex: %v", err)
		}

		err = s.Queries.UpdateInforByEmail(ctx, UpdateInforByEmailParams{
			Email: pgtype.Text{
				String: arg.Email,
				Valid:  true},
			Name:     arg.Name,
			Sex:      sex,
			BirthDay: arg.BirthDay})
		if err != nil {
			return fmt.Errorf("failed to update user information: %v", err)
		}

		_, err = s.Queries.UpdateUserAction(ctx, UpdateUserActionParams{
			Email: arg.Email,
			LoginAt: pgtype.Timestamptz{
				Valid: false,
			},
			LogoutAt: pgtype.Timestamptz{
				Valid: false,
			},
			UpdatedAt: pgtype.Timestamptz{
				Time:  time.Now(),
				Valid: true,
			},
		})
		if err != nil {
			return fmt.Errorf("failed to update user action: %v", err)
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("transaction failed: %v", err)
	}

	return err
}

func NewStore(connPool *pgxpool.Pool) IStore {
	return &SqlStore{
		connPool: connPool,
		Queries:  New(connPool),
	}
}
