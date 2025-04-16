package controllers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
	"user_service/dto/request"
	dto_response "user_service/dto/response"
	"user_service/global"
	"user_service/internal/responses"
	"user_service/internal/services"
	"user_service/utils/generator"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

var (
	google_oauth2_state_string   = "oauth2_google_state"
	facebook_oauth2_state_string = "oauth2_facebook_state"
)

type AuthController struct {
	RegistrationService   services.IRegistration
	LoginService          services.ILogin
	ForgotPasswordService services.IForgotPassword
	OAuth2Service         services.IOAuth2
	LogoutService         services.ILogout
	OAuth2GoogleConfig    *oauth2.Config
	OAuth2FacebookConfig  *oauth2.Config
}

func NewAuthController(
	registrationService services.IRegistration,
	loginService services.ILogin,
	forgotPasswordService services.IForgotPassword,
	oAuth2Service services.IOAuth2,
	logoutService services.ILogout,
	oAuth2GoogleConfig global.GoogleOAuthConfig,
	oAuth2FacebookConfig global.FacebookOAuthConfig) *AuthController {
	return &AuthController{
		RegistrationService:   registrationService,
		LoginService:          loginService,
		ForgotPasswordService: forgotPasswordService,
		OAuth2Service:         oAuth2Service,
		LogoutService:         logoutService,
		OAuth2GoogleConfig:    oAuth2GoogleConfig,
		OAuth2FacebookConfig:  oAuth2FacebookConfig,
	}
}

func (ac *AuthController) SendRegistrationOtp(c *gin.Context) {
	var req request.SendOtpReq
	if err := c.ShouldBindJSON(&req); err != nil {
		responses.FailureResponse(c, http.StatusBadRequest, "request is invalid")
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	status, err := ac.RegistrationService.SendRegistrationOtp(ctx, req)
	if err != nil {
		responses.FailureResponse(c, status, err.Error())
		return
	}

	responses.SuccessResponse(c, http.StatusOK, "send otp perform successfully", nil)
}

func (ac *AuthController) VerifyRegistrationOtp(c *gin.Context) {
	var req request.VerifyOtpReq
	if err := c.ShouldBindJSON(&req); err != nil {
		responses.FailureResponse(c, http.StatusBadRequest, "request is invalid")
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	status, err := ac.RegistrationService.VerifyRegistrationOtp(ctx, req)
	if err != nil {
		responses.FailureResponse(c, status, err.Error())
		return
	}

	responses.SuccessResponse(c, http.StatusOK, "verify otp perform successfully", nil)
}

func (ac *AuthController) CompleteRegistration(c *gin.Context) {
	var req request.CompleteRegistrationReq
	if err := c.ShouldBindJSON(&req); err != nil {
		responses.FailureResponse(c, http.StatusBadRequest, "request is invalid")
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	status, err := ac.RegistrationService.CompleteRegistration(ctx, req)
	if err != nil {
		responses.FailureResponse(c, status, err.Error())
		return
	}

	responses.SuccessResponse(c, http.StatusOK, "registration perform successfully", nil)
}

func (ac *AuthController) Login(c *gin.Context) {
	var req request.LoginReq
	if err := c.ShouldBindJSON(&req); err != nil {
		responses.FailureResponse(c, http.StatusBadRequest, "request is invalid")
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	data, status, err := ac.LoginService.Login(ctx, req)
	if err != nil {
		responses.FailureResponse(c, status, err.Error())
		return
	}

	responses.SuccessResponse(c, http.StatusOK, "login perform successfully", data)
}

func (ac *AuthController) SendForgotPasswordOtp(c *gin.Context) {
	var req request.SendOtpReq
	if err := c.ShouldBindJSON(&req); err != nil {
		responses.FailureResponse(c, http.StatusBadRequest, "request is invalid")
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	status, err := ac.ForgotPasswordService.SendForgotPasswordOtp(ctx, req)
	if err != nil {
		responses.FailureResponse(c, status, err.Error())
		return
	}

	responses.SuccessResponse(c, http.StatusOK, "send otp perform successfully", nil)
}

func (ac *AuthController) VerifyForgotPasswordOtp(c *gin.Context) {
	var req request.VerifyOtpReq
	if err := c.ShouldBindJSON(&req); err != nil {
		responses.FailureResponse(c, http.StatusBadRequest, "request is invalid")
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	status, err := ac.ForgotPasswordService.VerifyForgotPasswordOtp(ctx, req)
	if err != nil {
		responses.FailureResponse(c, status, err.Error())
		return
	}

	responses.SuccessResponse(c, http.StatusOK, "verifying otp for forgot password perform successfully", nil)
}

func (ac *AuthController) CompleteForgotPassword(c *gin.Context) {
	var req request.CompleteForgotPasswordReq
	if err := c.ShouldBindJSON(&req); err != nil {
		responses.FailureResponse(c, http.StatusBadRequest, "request is invalid")
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	status, err := ac.ForgotPasswordService.CompleteForgotPassword(ctx, req)
	if err != nil {
		responses.FailureResponse(c, status, err.Error())
		return
	}

	responses.SuccessResponse(c, http.StatusOK, "updating password perform successfully", nil)
}

func (ac *AuthController) Logout(c *gin.Context) {
	email := c.GetString("email")
	if email == "" {
		responses.FailureResponse(c, http.StatusBadRequest, "request is not exist")
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	status, err := ac.LogoutService.Logout(ctx, email)
	if err != nil {
		responses.FailureResponse(c, status, err.Error())
		return
	}

	responses.SuccessResponse(c, http.StatusOK, "logout perform successfully", nil)
}

func (ac *AuthController) GoogleLogin(c *gin.Context) {
	state, _ := generator.GenerateStringNumberBasedOnLength(24)

	http.SetCookie(c.Writer, &http.Cookie{
		Name:     google_oauth2_state_string,
		Value:    state,
		Expires:  time.Now().Add(5 * time.Minute),
		HttpOnly: true,
	})

	url := ac.OAuth2GoogleConfig.AuthCodeURL(state)

	c.Redirect(http.StatusTemporaryRedirect, url)
}

func (ac *AuthController) GoogleCallback(c *gin.Context) {
	state := c.Query("state")
	cookie, err := c.Request.Cookie(google_oauth2_state_string)
	if err != nil || cookie.Value != state {
		responses.FailureResponse(c, http.StatusUnauthorized, "invalid google oauth state")
		return
	}

	code := c.Query("code")
	// Exchange received code for access token
	token, err := ac.OAuth2GoogleConfig.Exchange(oauth2.NoContext, code)
	if err != nil {
		responses.FailureResponse(c, http.StatusBadRequest, fmt.Sprintf("code exchange failed: %v", err))
		return
	}
	// Get user information from Google
	response, err := http.Get(fmt.Sprintf("https://www.googleapis.com/oauth2/v2/userinfo?access_token=%s", token.AccessToken))
	if err != nil {
		responses.FailureResponse(c, http.StatusBadRequest, fmt.Sprintf("get google user information failed: %v", err))
		return
	}
	defer response.Body.Close()

	var userInfo dto_response.OAuth2UserInfo
	if err := json.NewDecoder(response.Body).Decode(&userInfo); err != nil {
		responses.FailureResponse(c, http.StatusBadRequest, fmt.Sprintf("decrypt google user information failed: %v", err))
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	// * Check if email is in db
	// * Case 1: If not, add to db and return token
	// * Case 2: If so, return the token.
	isExists, err := ac.OAuth2Service.CheckOAuth2UserByEmail(ctx, userInfo.Email)
	if err != nil {
		responses.FailureResponse(c, http.StatusInternalServerError, err.Error())
		return
	}
	if !isExists {
		status, err := ac.OAuth2Service.InserOAuth2UsertUser(ctx, userInfo)
		if err != nil {
			responses.FailureResponse(c, status, err.Error())
			return
		}

		data, status, err := ac.OAuth2Service.ReturnToken(ctx, userInfo.Email)
		if err != nil {
			responses.FailureResponse(c, status, err.Error())
			return
		}

		responses.SuccessResponse(c, http.StatusOK, "google login successfully", data)
	} else {
		data, status, err := ac.OAuth2Service.ReturnToken(ctx, userInfo.Email)
		if err != nil {
			responses.FailureResponse(c, status, err.Error())
			return
		}

		responses.SuccessResponse(c, http.StatusOK, "google login successfully", data)
	}
}

func (ac *AuthController) FacebookLogin(c *gin.Context) {
	state, _ := generator.GenerateStringNumberBasedOnLength(24)

	http.SetCookie(c.Writer, &http.Cookie{
		Name:     facebook_oauth2_state_string,
		Value:    state,
		Expires:  time.Now().Add(5 * time.Minute),
		HttpOnly: true,
	})

	url := ac.OAuth2FacebookConfig.AuthCodeURL(state)

	c.Redirect(http.StatusTemporaryRedirect, url)
}

func (ac *AuthController) FacebookgCallbak(c *gin.Context) {
	state := c.Query("state")
	cookie, err := c.Request.Cookie(facebook_oauth2_state_string)
	if err != nil || cookie.Value != state {
		responses.FailureResponse(c, http.StatusUnauthorized, "invalid facebook oauth state")
		return
	}

	code := c.Query("code")
	if code == "" {
		responses.FailureResponse(c, http.StatusBadRequest, "authentication code no found")
		return
	}

	token, err := ac.OAuth2FacebookConfig.Exchange(context.Background(), code)
	if err != nil {
		responses.FailureResponse(c, http.StatusBadRequest, fmt.Sprintf("code exchange failed: %v", err))
		return
	}

	response, err := http.Get("https://graph.facebook.com/me?fields=id,name,email,picture&access_token=" + token.AccessToken)
	if err != nil {
		responses.FailureResponse(c, http.StatusBadRequest, fmt.Sprintf("get facebook user information failed: %v", err))
		return
	}
	defer response.Body.Close()

	var user map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decode facebook user info"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	facebookUser := dto_response.OAuth2UserInfo{
		Id:    user["id"].(string),
		Email: user["email"].(string),
		Name:  user["name"].(string),
	}

	isExists, err := ac.OAuth2Service.CheckOAuth2UserByEmail(ctx, facebookUser.Email)
	if err != nil {
		responses.FailureResponse(c, http.StatusInternalServerError, err.Error())
		return
	}
	if !isExists {
		status, err := ac.OAuth2Service.InserOAuth2UsertUser(ctx, facebookUser)
		if err != nil {
			responses.FailureResponse(c, status, err.Error())
			return
		}

		data, status, err := ac.OAuth2Service.ReturnToken(ctx, facebookUser.Email)
		if err != nil {
			responses.FailureResponse(c, status, err.Error())
			return
		}

		responses.SuccessResponse(c, http.StatusOK, "facebook login successfully", data)
	} else {
		data, status, err := ac.OAuth2Service.ReturnToken(ctx, facebookUser.Email)
		if err != nil {
			responses.FailureResponse(c, status, err.Error())
			return
		}

		responses.SuccessResponse(c, http.StatusOK, "facebook login successfully", data)
	}
}
