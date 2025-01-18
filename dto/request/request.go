package request

type SendOTPReq struct {
	Email string `json:"email" binding:"required"`
}
