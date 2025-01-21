package response

type LoginRes struct {
	AccessToken  string      `json:"access_token" binding:"required"`
	RefreshToken string      `json:"refresh_token" binding:"required"`
	Payload      interface{} `json:"payload" binding:"required"`
}
