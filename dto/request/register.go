package request

type SendOtpReq struct {
	Email string `json:"email" binding:"required,email"`
}

type VerifyOtpReq struct {
	Email string `json:"email,omitempty" binding:"email"`
	Otp   string `json:"otp,omitempty" binding:"required,len=6"`
}

type Info struct {
	Name     string `json:"name" binding:"required"`
	Sex      string `json:"sex" binding:"required"`
	BirthDay string `json:"birth_day" binding:"required"`
}

type Account struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
	Role     string `json:"role" binding:"required"`
}

type CompleteRegistrationReq struct {
	Account Account `json:"account" binding:"required"`
	Info    Info    `json:"info" binding:"required"`
}
