package response

type LoginRes struct {
	AccessToken    string      `json:"access_token" binding:"required"`
	RefreshToken   string      `json:"refresh_token" binding:"required"`
	AccessPayload  interface{} `json:"access_payload" binding:"required"`
	RefreshPayload interface{} `json:"refresh_payload" binding:"required"`
}

type GetInfoRes struct {
	Email    string `json:"email" binding:"required,email"`
	Name     string `json:"name" binding:"required"`
	Sex      string `json:"sex" binding:"required"`
	BirthDay string `json:"birth_day" binding:"required"`
}
