package request

type SendOtpReq struct {
	Email string `json:"email" binding:"required,email"`
}

type VerifyOtpReq struct {
	Email string `json:"email,omitempty" binding:"email"`
	Otp   string `json:"otp,omitempty" binding:"required,len=6"`
}

type CompleteRegistrationReq struct {
	Account account `json:"account" binding:"required"`
	Info    info    `json:"info" binding:"required"`
}

type LoginReq struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type CompleteForgotPasswordReq struct {
	Email       string `json:"email" binding:"required,email"`
	NewPassword string `json:"new_password" binding:"required"`
}

// var AttemptData struct {
// 	Count int `json:"count" binding:"required"`
// }

type GetInforReq struct {
	Email string `json:"email" binding:"required,email"`
}

type LogoutReq struct {
	Token string `json:"token" binding:"required,token"`
}
