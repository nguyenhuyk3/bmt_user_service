package sqlc

import (
	"context"
	"user_service/dto/request"
)

type Store interface {
	Querier
	InsertAccountTran(ctx context.Context, arg request.CompleteRegisterReq) error
}
