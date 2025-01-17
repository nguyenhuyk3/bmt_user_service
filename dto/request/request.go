package request

type RegisterReq struct {
	Email string `json:"email" binding:"required"`
}
