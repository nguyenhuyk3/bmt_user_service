package global

const (
	REDIS_REGISTRATION_OTP_KEY          = "opt::"
	REDIS_COMPLETE_REGISTRATION_PROCESS = "complete_registration_process::"
)

// These keys below will be used for forgot password purposes
const (
	FORGOT_PASSWORD_KEY              = "forgot_password::"
	ATTEMPT_KEY                      = "ettempt::"
	BLOCK_FORGOT_PASSWORD_KEY        = "block_forgot_password_key::"
	COMPLETE_FORGOT_PASSWORD_PROCESS = "complete_forgot_password_process::"
)

const (
	REDIS_BLACK_LIST = "black_list::"
)
