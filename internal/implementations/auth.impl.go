package implementations

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"time"
	"user_service/db/sqlc"
	"user_service/dto/messages"
	"user_service/dto/request"
	"user_service/dto/response"
	"user_service/global"
	"user_service/internal/services"
	"user_service/utils/cryptor"
	"user_service/utils/generator"
	"user_service/utils/token/jwt"

	"github.com/jackc/pgx/v5/pgtype"
)

type authService struct {
	SqlStore      sqlc.IStore
	JwtMaker      jwt.IMaker
	RedisClient   services.IRedis
	MessageBroker services.IMessageBroker
}

func NewAuthService(
	sqlStore sqlc.IStore,
	jwtMaker jwt.IMaker,
	redisClient services.IRedis,
	messageBroker services.IMessageBroker) services.IAuth {
	return &authService{
		SqlStore:      sqlStore,
		JwtMaker:      jwtMaker,
		RedisClient:   redisClient,
		MessageBroker: messageBroker,
	}
}

const (
	ten_minutes   = 10
	three_minutes = 3
	three_hours   = 3 * 60
)

// Login implements services.IAuthUser.
func (a *authService) Login(ctx context.Context, arg request.LoginReq) (response.LoginRes, int, error) {
	var result response.LoginRes

	user, err := a.SqlStore.GetUserByEmail(ctx, arg.Email)
	if err != nil {
		if err == sql.ErrNoRows {
			return response.LoginRes{}, http.StatusNotFound, errors.New("user not found")
		}

		return response.LoginRes{}, http.StatusInternalServerError, fmt.Errorf("failed to fetch user: %w", err)
	}

	isMatch := cryptor.BcryptCheckInput(user.Password, arg.Password)
	if isMatch != nil {
		return response.LoginRes{}, http.StatusUnauthorized, errors.New("password does not match")
	}

	accessToken, accessPayload, err := a.JwtMaker.CreateAccessToken(user.Email, string(user.Role.Roles))
	if err != nil {
		return response.LoginRes{}, http.StatusInternalServerError, fmt.Errorf("failed to create access token: %w", err)
	}
	result.AccessToken = accessToken
	result.AccessPayload = accessPayload

	refreshToken, _, err := a.JwtMaker.CreateRefreshToken(user.Email, string(user.Role.Roles))
	if err != nil {
		return response.LoginRes{}, http.StatusInternalServerError, fmt.Errorf("failed to create refresh token: %w", err)
	}
	result.RefreshToken = refreshToken

	_, err = a.SqlStore.UpdateAction(ctx, sqlc.UpdateActionParams{
		Email: user.Email,
		LoginAt: pgtype.Timestamptz{
			Time:  time.Now(),
			Valid: true,
		},
		LogoutAt: pgtype.Timestamptz{
			Valid: false,
		},
	})
	if err != nil {
		return response.LoginRes{}, http.StatusInternalServerError, fmt.Errorf("failed to update user action: %w", err)
	}

	return result, http.StatusOK, nil
}

/*
* SendForgotPasswordOtp will include 6 steps:
*	- Step 1: Check if the email exists before
*	- Step 2: Check if this email is locked (check blockKey) or not (avoid spam)
*	- Step 3: Check how many times this email has been sent, if more than 2 times, a key (blockKey) will be created in redis (within 3 hours)
*	- Step 4: Check if the email has an expired otp code or not (check forgotPasswordKey), because each email will exist for 3 minutes and after 3 minutes it can only be sent once more
*	- Step 5: If it passes the above conditions, the email will be sent
*	- Step 6: If the email is sent successfully, we will increase the attempKey by 1
 */
// SendForgotPasswordOtp implements services.IAuth.
func (a *authService) SendForgotPasswordOtp(ctx context.Context, arg request.SendOtpReq) (int, error) {
	// * Step 1
	isExists, err := a.SqlStore.CheckAccountExistsByEmail(ctx, arg.Email)
	if err != nil {
		return http.StatusInternalServerError, errors.New("failed to check email existence in database")
	}

	if !isExists {
		return http.StatusNotFound, errors.New("email doesn't exist")
	}

	aesEncryptedEmail, _ := cryptor.AesEncrypt(arg.Email)
	// * Step 2
	// This key will keep track of how many times the email has been sent.
	attemptKey := fmt.Sprintf("%s%s", global.ATTEMPT_KEY, aesEncryptedEmail)
	// Check if this key has been blocked due to exceeding 3 email attempts
	blockKey := fmt.Sprintf("%s%s", global.BLOCK_FORGOT_PASSWORD_KEY, aesEncryptedEmail)
	blockedTTL, err := a.RedisClient.GetTTL(blockKey)
	if err == nil && blockedTTL > 0 {
		_ = a.RedisClient.Delete(attemptKey)
		return http.StatusTooManyRequests, fmt.Errorf("you cannot make a request in: %v", blockedTTL)
	}

	// * Step 3
	var res blockSendForgotPasswordOtp

	err = a.RedisClient.Get(attemptKey, &res)
	if err != nil {
		// This code will be perform at first
		res.Count = 0
		_ = a.RedisClient.Save(attemptKey, res, three_hours)
	}

	if res.Count > 2 {
		_ = a.RedisClient.Save(blockKey, map[string]interface{}{
			"blocked": true,
		}, three_hours)
		_ = a.RedisClient.Delete(attemptKey)

		return http.StatusTooManyRequests, errors.New("you can't do the request in 3 hours")
	}
	// * Step 4
	// This key will hold the value of the otp code
	forgotPasswordKey := fmt.Sprintf("%s%s", global.FORGOT_PASSWORD_KEY, aesEncryptedEmail)
	// Check remaining time of this key
	remainingTime, _ := a.RedisClient.GetTTL(forgotPasswordKey)
	if remainingTime > 0 {
		return http.StatusTooManyRequests, fmt.Errorf("please try again later %v", remainingTime)
	}
	// * Step 5
	otp, _ := generator.GenerateStringNumberBasedOnLength(6)
	message := messages.MailMessage{
		Payload: messages.OtpMessage{
			Email:          arg.Email,
			Otp:            otp,
			ExpirationTime: three_minutes,
		},
	}
	// * Step 6
	err = a.MessageBroker.SendMessage(
		ctx,
		global.FORGOT_PASSWORD_OTP_EMAIL_TOPIC,
		arg.Email,
		message)
	if err == nil {
		bcryptEncryptedEmail, _ := cryptor.BcryptHashInput(arg.Email)
		_ = a.RedisClient.Save(forgotPasswordKey, map[string]interface{}{
			"encrypted_email": bcryptEncryptedEmail,
			"otp":             otp,
		}, three_minutes)

		res.Count++
		_ = a.RedisClient.Save(attemptKey, res, three_hours)

		return http.StatusOK, nil
	} else {
		_ = a.RedisClient.Delete(attemptKey)

		return http.StatusInternalServerError, fmt.Errorf("send mail failed: %v", err)
	}
}

// VerifyForgotPasswordOtp implements services.IAuth.
func (a *authService) VerifyForgotPasswordOtp(ctx context.Context, arg request.VerifyOtpReq) (int, error) {
	aesEncryptedEmail, _ := cryptor.AesEncrypt(arg.Email)
	forgotPasswordKey := fmt.Sprintf("%s%s", global.FORGOT_PASSWORD_KEY, aesEncryptedEmail)

	var result verifyOtp
	err := a.RedisClient.Get(forgotPasswordKey, &result)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	isMatch := cryptor.BcryptCheckInput(result.EncryptedEmail, arg.Email)
	if isMatch == nil && arg.Otp == result.Otp {
		_ = a.RedisClient.Delete(forgotPasswordKey)
		_ = a.RedisClient.Save(fmt.Sprintf("%s%s", global.COMPLETE_FORGOT_PASSWORD_PROCESS, aesEncryptedEmail),
			map[string]interface{}{
				"encrypted_email": result.EncryptedEmail,
			}, ten_minutes)

		return http.StatusOK, nil
	}

	return http.StatusUnauthorized, fmt.Errorf("invalid otp")
}

// CompleForgotPassword implements services.IAuth.
func (a *authService) CompleteForgotPassword(ctx context.Context, arg request.CompleteForgotPasswordReq) (int, error) {
	aesEncryptedEmail, _ := cryptor.AesEncrypt(arg.Email)
	key := fmt.Sprintf("%s%s", global.COMPLETE_FORGOT_PASSWORD_PROCESS, aesEncryptedEmail)
	isExists := a.RedisClient.ExistsKey(key)
	if !isExists {
		return http.StatusConflict, errors.New("invalid request for complete forgot password")
	}

	var result verifyOtp
	err := a.RedisClient.Get(key, &result)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	isMatch := cryptor.BcryptCheckInput(result.EncryptedEmail, arg.Email)
	if isMatch != nil {
		return http.StatusUnauthorized, errors.New("email mismatch or invalid request")
	}

	newPassword, _ := cryptor.BcryptHashInput(arg.NewPassword)
	err = a.SqlStore.UpdatePassword(ctx, sqlc.UpdatePasswordParams{
		Email:    arg.Email,
		Password: newPassword,
	})
	if err != nil {
		return http.StatusInternalServerError, err
	}

	_ = a.RedisClient.Delete(fmt.Sprintf("%s%s", global.ATTEMPT_KEY, aesEncryptedEmail))
	_ = a.RedisClient.Delete(key)

	return http.StatusOK, nil
}

// Logout implements services.IAuth.
func (a *authService) Logout(ctx context.Context, email string) (int, error) {
	_, err := a.SqlStore.UpdateAction(ctx, sqlc.UpdateActionParams{
		Email: email,
		LoginAt: pgtype.Timestamptz{
			Valid: false,
		},
		LogoutAt: pgtype.Timestamptz{
			Time:  time.Now(),
			Valid: true,
		},
	})
	if err != nil {
		return http.StatusInternalServerError, err
	}

	return http.StatusOK, nil
}

// InsertGoogleUser implements services.IAuth.
func (a *authService) InserOAuth2UsertUser(ctx context.Context, arg response.OAuth2UserInfo) (int, error) {
	hasedPassword, _ := cryptor.BcryptHashInput(arg.Id)
	err := a.SqlStore.InsertAccountTran(ctx, request.CompleteRegistrationReq{
		Account: request.Account{
			Email:    arg.Email,
			Password: hasedPassword,
			Role:     global.CUSTOMER_ROLE,
		},
		Info: request.Info{
			Name:     arg.Name,
			Sex:      global.MALE,
			BirthDay: "",
		},
	}, true)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("an error occur when insert to db: %v", err)
	}

	return http.StatusOK, nil
}

// CheckOAuth2UserByEmail implements services.IAuth.
func (a *authService) CheckOAuth2UserByEmail(ctx context.Context, email string) (bool, error) {
	isExists, err := a.SqlStore.CheckAccountExistsByEmail(ctx, email)
	if err != nil {
		return false, fmt.Errorf("an error occur when querying to db: %v", err)
	}
	if isExists {
		return isExists, fmt.Errorf("this email has been registered")
	} else {
		return isExists, nil
	}
}

// ReturnToken implements services.IAuth.
func (a *authService) ReturnToken(ctx context.Context, email string) (response.LoginRes, int, error) {
	accessToken, payload, err := a.JwtMaker.CreateAccessToken(email, global.CUSTOMER_ROLE)
	if err != nil {
		return response.LoginRes{}, http.StatusInternalServerError, fmt.Errorf("an error occur when creating jwt access token: %v", err)
	}
	refreshToken, _, err := a.JwtMaker.CreateRefreshToken(email, global.CUSTOMER_ROLE)
	if err != nil {
		return response.LoginRes{}, http.StatusInternalServerError, fmt.Errorf("an error occur when creating jwt refrest token: %v", err)
	}

	return response.LoginRes{
		AccessToken:   accessToken,
		AccessPayload: payload,
		RefreshToken:  refreshToken,
	}, http.StatusOK, nil
}
