package response

type GetInfoRes struct {
	Email    string `json:"email" binding:"required,email"`
	Name     string `json:"name" binding:"required"`
	Sex      string `json:"sex" binding:"required"`
	BirthDay string `json:"birth_day" binding:"required"`
}

type GoogleUserInfo struct {
	Email         string `json:"email" binding:"required"`
	GivenName     string `json:"given_name" binding:"required"`
	Id            string `json:"id" binding:"required"`
	Name          string `json:"name" binding:"required"`
	Picture       string `json:"picture" binding:"required"`
	VerifiedEmail bool   `json:"verified_email" binding:"required"`
}
