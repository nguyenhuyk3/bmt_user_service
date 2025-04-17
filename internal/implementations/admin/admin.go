package admin

import (
	"context"
	"fmt"
	"net/http"
	"user_service/db/sqlc"
	"user_service/dto/request"
	"user_service/dto/response"
	"user_service/internal/services"

	"github.com/jackc/pgx/v5/pgtype"
)

type adminService struct {
	SqlStore sqlc.IStore
}

// CreateAdminAccount implements services.IAdmin.
func (c *adminService) CreateAdminAccount(ctx context.Context, arg request.CreateAdminAccountReq) (int, error) {
	err := c.SqlStore.InsertAccountTran(ctx, request.CompleteRegistrationReq{
		Account: request.Account{
			Email:    arg.AdminAccount.Email,
			Password: arg.AdminAccount.Password,
			Role:     "manage"},
		Info: request.Info{
			Name:     arg.Info.Name,
			Sex:      arg.Info.Sex,
			BirthDay: arg.Info.BirthDay},
	}, false)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("failed to complete registration: %w", err)
	}

	return http.StatusOK, nil
}

// UpdateUserInfor implements services.IAdmin.
func (c *adminService) UpdateUserInfor(ctx context.Context, arg request.ChangeInforReq) (int, error) {
	err := c.SqlStore.UpdateUserInforTran(ctx, arg)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	return http.StatusOK, nil
}

// GetInfor implements services.IAdmin.
func (c *adminService) GetInfor(ctx context.Context, arg request.GetInforReq) (response.GetInfoRes, int, error) {
	infor, err := c.SqlStore.GetInforByEmail(ctx, pgtype.Text{
		String: arg.Email,
		Valid:  true,
	})
	if err != nil {
		return response.GetInfoRes{}, http.StatusInternalServerError, fmt.Errorf("error occurs when get info: %v", err)
	}

	data := response.GetInfoRes{
		Email:    infor.Email.String,
		Name:     infor.Name,
		Sex:      string(infor.Sex.Sex),
		BirthDay: infor.BirthDay,
	}

	return data, http.StatusOK, nil
}

func NewAdminService(sqlStore sqlc.IStore) services.IAdmin {
	return &adminService{
		SqlStore: sqlStore,
	}
}
