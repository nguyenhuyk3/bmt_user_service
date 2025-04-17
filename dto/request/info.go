package request

type GetInforReq struct {
	Email string `json:"email" binding:"required,email"`
}

type ChangeInforReq struct {
	Email    string
	Name     string `json:"name" binding:"required"`
	Sex      string `json:"sex" binding:"required"`
	BirthDay string `json:"birth_day" binding:"required"`
}
