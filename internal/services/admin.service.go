package services

import (
	"context"
	"user_service/dto/request"
)

type IAdmin interface {
	IUser
	CreateAdminAccount(ctx context.Context, arg request.CreateAdminAccountReq) (int, error)
}
