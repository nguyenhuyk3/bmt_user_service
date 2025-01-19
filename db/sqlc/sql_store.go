package sqlc

import (
	"context"
	"fmt"
	"user_service/dto/request"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type SqlStore struct {
	connPool *pgxpool.Pool
	*Queries
}

func NewStore(connPool *pgxpool.Pool) *SqlStore {
	return &SqlStore{
		connPool: connPool,
		Queries:  New(connPool),
	}
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

// InsertFullAccount implements Store.
func (s *SqlStore) InsertAccountTran(ctx context.Context, arg request.CompleteRegisterReq) error {
	err := s.execTran(ctx, func(q *Queries) error {
		var err error

		var role NullRoles
		err = role.Scan(arg.Account)
		if err != nil {

		}
		err = q.InsertAccount(ctx, InsertAccountParams{
			Email:    arg.Account.Email,
			Password: arg.Account.Password,
			Role:     role,
		})

		if err != nil {
			return err
		}

		var sex NullSex
		err = sex.Scan(arg.Info.Sex)
		if err != nil {

		}

		err = q.InsertUserInfo(ctx, InsertUserInfoParams{
			AccountEmail: pgtype.Text{
				String: arg.Account.Email,
			},
			Name:     arg.Info.Name,
			Sex:      sex,
			BirthDay: arg.Info.BirthDay,
		})

		if err != nil {
			return err
		}

		err = q.InsertUserAction(ctx, pgtype.Text{
			String: arg.Account.Email,
		})

		if err != nil {
			return err
		}

		return err
	})

	return err
}
