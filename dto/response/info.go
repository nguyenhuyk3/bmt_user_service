package response

type GetInfoRes struct {
	Email    string `json:"email" binding:"required,email"`
	Name     string `json:"name" binding:"required"`
	Sex      string `json:"sex" binding:"required"`
	BirthDay string `json:"birth_day" binding:"required"`
}

type OAuth2UserInfo struct {
	Id            string `json:"id" binding:"required"`
	Email         string `json:"email" binding:"required"`
	Name          string `json:"name" binding:"required"`
	GivenName     string `json:"given_name,omitempty"`
	Picture       string `json:"picture,omitempty"`
	VerifiedEmail bool   `json:"verified_email,omitempty"`
}
