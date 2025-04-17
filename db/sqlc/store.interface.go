package sqlc

import (
	"context"
	"user_service/dto/request"
)

//go:generate mockgen -source=store.interface.go -destination=../../internal/mocks/store.mock.go -package=mocks

type IStore interface {
	Querier
	InsertAccountTran(ctx context.Context, arg request.CompleteRegistrationReq, isFromOAuth2 bool) error
	UpdateUserInforTran(ctx context.Context, arg request.ChangeInforReq) error
}
