package request

type LogoutReq struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}
