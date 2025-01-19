package request

type SendOtpReq struct {
	Email string `json:"email" binding:"required"`
}

type VerifyOtpReq struct {
	Email string `json:"email" binding:"required,email"`
	Otp   string `json:"otp" binding:"required,len=6"`
}

type CompleteRegistrationReq struct {
	Account account `json:"account" binding:"required"`
	Info    info    `json:"info" binding:"required"`
}
