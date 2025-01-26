package implementations

type blockSendForgotPasswordOtp struct {
	Count int `json:"count" binding:"required"`
}

type verifyOtp struct {
	EncryptedEmail string `json:"encrypted_email" binding:"required"`
	Otp            string `json:"otp" binding:"required"`
}
