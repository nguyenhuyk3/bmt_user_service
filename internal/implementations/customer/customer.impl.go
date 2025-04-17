package customer

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

type customerService struct {
	SqlStore sqlc.IStore
}

// UpdateUserInfor implements services.ICustomer.
func (c *customerService) UpdateUserInfor(ctx context.Context, arg request.ChangeInforReq) (int, error) {
	err := c.SqlStore.UpdateUserInforTran(ctx, arg)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	return http.StatusOK, nil
}

// GetInfor implements services.ICustomer.
func (c *customerService) GetInfor(ctx context.Context, arg request.GetInforReq) (response.GetInfoRes, int, error) {
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

func NewCustomerService(sqlStore sqlc.IStore) services.ICustomer {
	return &customerService{
		SqlStore: sqlStore,
	}
}
