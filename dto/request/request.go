package request

type SendOtpReq struct {
	Email string `json:"email" binding:"required,email"`
}

type VerifyOtpReq struct {
	Email          string `json:"email,omitempty" binding:"required,email"`
	EncryptedEmail string `json:"encrypted_email" binding:"required"`
	Otp            string `json:"otp" binding:"required,len=6"`
}

type CompleteRegistrationReq struct {
	EncryptedEmail string  `json:"encrypted_email" binding:"required"`
	Account        account `json:"account" binding:"required"`
	Info           info    `json:"info" binding:"required"`
}
