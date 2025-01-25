package request

type SendOtpReq struct {
	Email string `json:"email" binding:"required,email"`
}

type VerifyOtpReq struct {
	Email          string `json:"email,omitempty" binding:"email"`
	EncryptedEmail string `json:"encrypted_email" binding:"required"`
	Otp            string `json:"otp,omitempty" binding:"required,len=6"`
}

type CompleteRegistrationReq struct {
	Account account `json:"account" binding:"required"`
	Info    info    `json:"info" binding:"required"`
}

type LoginReq struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}
