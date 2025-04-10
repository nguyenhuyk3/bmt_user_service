package response

type LoginRes struct {
	AccessToken   string      `json:"access_token" binding:"required"`
	RefreshToken  string      `json:"refresh_token" binding:"required"`
	AccessPayload interface{} `json:"access_payload" binding:"required"`
	// RefreshPayload interface{} `json:"refresh_payload" binding:"required"`
}
