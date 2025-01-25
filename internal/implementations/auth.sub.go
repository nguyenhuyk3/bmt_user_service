package implementations

type blockSendForgotPasswordOtp struct {
	Count int `json:"count" binding:"required"`
}

type completeRegistration struct {
	EncryptedEmail string `json:"encrypted_email"  binding:"required"`
}
