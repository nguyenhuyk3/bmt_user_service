package services

import (
	"context"
	"user_service/dto/request"
	"user_service/dto/response"
)

type IUser interface {
	GetInfor(ctx context.Context, arg request.GetInforReq) (response.GetInfoRes, int, error)
}
