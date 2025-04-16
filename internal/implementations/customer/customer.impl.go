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

func NewCustomerService(sqlStore sqlc.IStore) services.ICustomer {
	return &customerService{
		SqlStore: sqlStore,
	}
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
