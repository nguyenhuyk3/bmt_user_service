package request

type SendOtpReq struct {
	Email string `json:"email" binding:"required,email"`
}

type VerifyOtpReq struct {
	Email string `json:"email,omitempty" binding:"email"`
	Otp   string `json:"otp,omitempty" binding:"required,len=6"`
}

type info struct {
	Name     string `json:"name" binding:"required"`
	Sex      string `json:"sex" binding:"required"`
	BirthDay string `json:"birth_day" binding:"required"`
}

type account struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
	Role     string `json:"role" binding:"required"`
}

type CompleteRegistrationReq struct {
	Account account `json:"account" binding:"required"`
	Info    info    `json:"info" binding:"required"`
}
