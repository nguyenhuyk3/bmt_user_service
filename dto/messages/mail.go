package messages

type MailMessage struct {
	Type    string      `json:"type" binding:"required"`
	Payload interface{} `json:"payload" binding:"required"`
}

type OtpMessage struct {
	Email          string `json:"email" binding:"required"`
	Otp            string `json:"otp" binding:"required"`
	ExpirationTime int    `json:"expiration_time" binding:"required"`
}
