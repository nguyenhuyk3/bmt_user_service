package request

type GetInforReq struct {
	Email string `json:"email" binding:"required,email"`
}
