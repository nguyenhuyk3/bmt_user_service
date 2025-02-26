package implementations

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
	"user_service/db/sqlc"
	"user_service/dto/request"
	"user_service/dto/response"
	"user_service/global"
	"user_service/internal/services"
	"user_service/utils/cryptor"
	"user_service/utils/generator"
	"user_service/utils/redis"
	mail "user_service/utils/sender"
	"user_service/utils/token/jwt"

	"github.com/jackc/pgx/v5/pgtype"
)

type authService struct {
	SqlStore *sqlc.SqlStore
	JwtMaker jwt.IMaker
}

func NewAuthService(sqlStore *sqlc.SqlStore, jwtMaker jwt.IMaker) services.IAuth {
	return &authService{
		SqlStore: sqlStore,
		JwtMaker: jwtMaker,
	}
}

const (
	ten_minutes   = 10
	three_minutes = 3
	three_hours   = 3 * 60
)

// SendRegistrationOtp implements services.IAuthUser.
func (a *authService) SendRegistrationOtp(ctx context.Context, arg request.SendOtpReq) (int, error) {
	// Check if email has otp in redis or not
	encryptedAesEmail, _ := cryptor.AesEncrypt(arg.Email)
	registrationOtpKey := fmt.Sprintf("%s%s", global.REDIS_REGISTRATION_OTP_KEY, encryptedAesEmail)

	isExists := redis.ExistsKey(registrationOtpKey)
	if isExists {
		return http.StatusConflict, errors.New("email is in registration status")
	}

	completeRegistrationProcessKey := fmt.Sprintf("%s%s", global.REDIS_COMPLETE_REGISTRATION_PROCESS, encryptedAesEmail)

	isExists = redis.ExistsKey(completeRegistrationProcessKey)
	if isExists {
		return http.StatusConflict, errors.New("email is in complete registration process")
	}

	// Check if email already exists or not
	isExists, err := a.SqlStore.Queries.CheckAccountExistsByEmail(ctx, arg.Email)
	if err != nil {
		return http.StatusInternalServerError, errors.New("failed to check email existence in database")
	}

	if isExists {
		return http.StatusConflict, errors.New("email already exists")
	}

	otp, _ := generator.GenerateNumberBasedOnLength(6)
	encryptedBcryptEmail, _ := cryptor.BcryptHashInput(arg.Email)
	// Save email and otp is in registration status
	_ = redis.Save(registrationOtpKey, verifyOtp{
		EncryptedEmail: encryptedBcryptEmail,
		Otp:            otp,
	}, ten_minutes)
	err = mail.SendTemplateEmailOtp([]string{arg.Email},
		global.Config.Server.FromEmail,
		"registration_otp_email.html",
		global.REGISTRATION_PURPOSE,
		map[string]interface{}{
			"otp":             otp,
			"from_email":      global.Config.Server.FromEmail,
			"expiration_time": ten_minutes,
		})

	if err != nil {
		redis.Delete(registrationOtpKey)
		return http.StatusInternalServerError, errors.New("failed to send mail, please try again later")
	}

	return http.StatusOK, nil
}

// VerifyRegistrationOtp implements services.IAuthUser.
func (a *authService) VerifyRegistrationOtp(ctx context.Context, arg request.VerifyOtpReq) (int, error) {
	encryptedEmail, _ := cryptor.AesEncrypt(arg.Email)
	key := fmt.Sprintf("%s%s", global.REDIS_REGISTRATION_OTP_KEY, encryptedEmail)

	var result verifyOtp

	err := redis.Get(key, &result)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("otp has expired: %v", err)
	}

	isMatch := cryptor.BcryptCheckInput(result.EncryptedEmail, arg.Email)
	if isMatch == nil && arg.Otp == result.Otp {
		_ = redis.Delete(key)
		_ = redis.Save(fmt.Sprintf("%s%s", global.REDIS_COMPLETE_REGISTRATION_PROCESS, encryptedEmail),
			map[string]interface{}{
				"encrypted_email": result.EncryptedEmail,
			}, ten_minutes)

		return http.StatusOK, nil
	}

	return http.StatusUnauthorized, fmt.Errorf("invalid email or otp")
}

// CompleteRegister implements services.IAuth.
func (a *authService) CompleteRegistration(ctx context.Context, arg request.CompleteRegistrationReq) (int, error) {
	encryptedEmail, _ := cryptor.AesEncrypt(arg.Account.Email)
	key := fmt.Sprintf("%s%s", global.REDIS_COMPLETE_REGISTRATION_PROCESS, encryptedEmail)

	var result verifyOtp

	err := redis.Get(key, &result)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("email is not in complete registration process %v", err)
	}

	isMatch := cryptor.BcryptCheckInput(result.EncryptedEmail, arg.Account.Email)
	if isMatch != nil {
		return http.StatusBadRequest, errors.New("encrypted email and email don't match")
	}

	err = a.SqlStore.InsertAccountTran(ctx, arg)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("failed to complete registration: %w", err)
	}

	_ = redis.Delete(key)

	return http.StatusCreated, nil
}

// Login implements services.IAuthUser.
func (a *authService) Login(ctx context.Context, arg request.LoginReq) (response.LoginRes, int, error) {
	var result response.LoginRes

	user, err := a.SqlStore.Queries.GetUserByEmail(ctx, arg.Email)
	if err != nil {
		if err == sql.ErrNoRows {
			return result, http.StatusNotFound, errors.New("user not found")
		}

		return result, http.StatusInternalServerError, fmt.Errorf("failed to fetch user: %w", err)
	}

	isMatch := cryptor.BcryptCheckInput(user.Password, arg.Password)
	if isMatch != nil {
		return result, http.StatusUnauthorized, errors.New("password does not match")
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var errChan = make(chan error, 3)

	wg.Add(1)
	go func() {
		defer wg.Done()

		token, payload, err := a.JwtMaker.CreateAccessToken(user.Email, string(user.Role.Roles))

		mu.Lock()

		defer mu.Unlock()

		if err != nil {
			errChan <- fmt.Errorf("failed to create access token: %w", err)
			return
		}

		result.AccessToken = token
		result.AccessPayload = payload
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()

		token, payload, err := a.JwtMaker.CreateRefreshToken(user.Email, string(user.Role.Roles))

		mu.Lock()

		defer mu.Unlock()
		if err != nil {
			errChan <- fmt.Errorf("failed to create refresh token: %w", err)
			return
		}

		result.RefreshToken = token
		result.RefreshPayload = payload
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()

		_, err := a.SqlStore.Queries.UpdateAction(ctx, sqlc.UpdateActionParams{
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
			errChan <- fmt.Errorf("failed to update user_action: %w", err)
		}
	}()

	wg.Wait()
	close(errChan)

	for err := range errChan {
		if err != nil {
			return result, http.StatusInternalServerError, err
		}
	}

	return result, http.StatusOK, nil
}

// SendForgotPasswordOtp implements services.IAuth.
func (a *authService) SendForgotPasswordOtp(ctx context.Context, arg request.SendOtpReq) (int, error) {
	isExists, err := a.SqlStore.Queries.CheckAccountExistsByEmail(ctx, arg.Email)
	if err != nil {
		return http.StatusInternalServerError, errors.New("failed to check email existence in database")
	}

	if !isExists {
		return http.StatusNotFound, errors.New("email doesn't exist")
	}

	aesEncryptedEmail, _ := cryptor.AesEncrypt(arg.Email)
	// This key will keep track of how many times the email has been sent.
	attemptKey := fmt.Sprintf("%s%s", global.ATTEMPT_KEY, aesEncryptedEmail)
	// Check if this key has been blocked due to exceeding 3 email attempts
	blockKey := fmt.Sprintf("%s%s", global.BLOCK_FORGOT_PASSWORD_KEY, aesEncryptedEmail)

	blockedTTL, err := redis.GetTTL(blockKey)
	if err == nil && blockedTTL > 0 {
		_ = redis.Delete(attemptKey)
		return http.StatusTooManyRequests, fmt.Errorf("you cannot make a request in: %v", blockedTTL)
	}

	var res blockSendForgotPasswordOtp

	err = redis.Get(attemptKey, &res)
	if err != nil {
		res.Count = 0
		_ = redis.Save(attemptKey, res, three_hours)
	}

	if res.Count > 2 {
		_ = redis.Save(blockKey, map[string]interface{}{
			"blocked": true,
		}, three_hours)
		_ = redis.Delete(attemptKey)

		return http.StatusTooManyRequests, errors.New("you can't do the request in 3 hours")
	}
	// This key will hold the value of the otp code
	forgotPasswordKey := fmt.Sprintf("%s%s", global.FORGOT_PASSWORD_KEY, aesEncryptedEmail)
	// Check remaining time of this key
	remainingTime, _ := redis.GetTTL(forgotPasswordKey)
	if remainingTime > 0 {
		return http.StatusTooManyRequests, fmt.Errorf("please try again later %v", remainingTime)
	}

	otp, _ := generator.GenerateNumberBasedOnLength(6)
	err = mail.SendTemplateEmailOtp([]string{arg.Email},
		global.Config.Server.FromEmail,
		"forgot_password_otp_email.html",
		global.FORGOT_PASSWORD_PURPOSE,
		map[string]interface{}{
			"otp":             otp,
			"from_email":      global.Config.Server.FromEmail,
			"expiration_time": three_minutes,
		})
	if err == nil {
		bcryptEncryptedEmail, _ := cryptor.BcryptHashInput(arg.Email)
		_ = redis.Save(forgotPasswordKey, map[string]interface{}{
			"encrypted_email": bcryptEncryptedEmail,
			"otp":             otp,
		}, three_minutes)

		res.Count++
		_ = redis.Save(attemptKey, res, three_hours)

		return http.StatusOK, nil
	} else {
		_ = redis.Delete(attemptKey)

		return http.StatusInternalServerError, fmt.Errorf("send mail failed: %v", err)
	}
}

// VerifyForgotPasswordOtp implements services.IAuth.
func (a *authService) VerifyForgotPasswordOtp(ctx context.Context, arg request.VerifyOtpReq) (int, error) {
	aesEncryptedEmail, _ := cryptor.AesEncrypt(arg.Email)
	forgotPasswordKey := fmt.Sprintf("%s%s", global.FORGOT_PASSWORD_KEY, aesEncryptedEmail)

	var result verifyOtp
	err := redis.Get(forgotPasswordKey, &result)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	isMatch := cryptor.BcryptCheckInput(result.EncryptedEmail, arg.Email)
	if isMatch == nil && arg.Otp == result.Otp {
		_ = redis.Delete(forgotPasswordKey)
		_ = redis.Save(fmt.Sprintf("%s%s", global.COMPLETE_FORGOT_PASSWORD_PROCESS, aesEncryptedEmail),
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
	isExists := redis.ExistsKey(key)
	if !isExists {
		return http.StatusConflict, errors.New("invalid request for complete forgot password")
	}

	var result verifyOtp
	err := redis.Get(key, &result)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	isMatch := cryptor.BcryptCheckInput(result.EncryptedEmail, arg.Email)
	if isMatch != nil {
		return http.StatusUnauthorized, errors.New("email mismatch or invalid request")
	}

	newPassword, _ := cryptor.BcryptHashInput(arg.NewPassword)
	err = a.SqlStore.Queries.UpdatePassword(ctx, sqlc.UpdatePasswordParams{
		Email:    arg.Email,
		Password: newPassword,
	})
	if err != nil {
		return http.StatusInternalServerError, err
	}

	_ = redis.Delete(fmt.Sprintf("%s%s", global.ATTEMPT_KEY, aesEncryptedEmail))
	_ = redis.Delete(key)

	return http.StatusOK, nil
}

// Logout implements services.IAuth.
func (a *authService) Logout(ctx context.Context, email string) (int, error) {
	_, err := a.SqlStore.Queries.UpdateAction(ctx, sqlc.UpdateActionParams{
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
