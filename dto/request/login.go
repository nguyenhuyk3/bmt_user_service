package request

type LoginReq struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type EmailAndSource struct {
	Email  string
	Source string
}
