package middlewares

import (
	"fmt"
	"net/http"
	"strings"
	"time"
	"user_service/dto/request"
	"user_service/global"
	"user_service/internal/responses"
	"user_service/utils/redis"
	"user_service/utils/token/jwt"

	"github.com/gin-gonic/gin"
)

const (
	access_token        = "access_token"
	refresh_token       = "refresh_token"
	x_refresh_token     = "X-Refresh-Token"
	x_new_refresh_token = "X-New-Refresh-Token"
)

type AuthMiddleware struct {
	JwtMaker jwt.IMaker
}

func NewAuthMiddleware(jwtMake jwt.IMaker) *AuthMiddleware {
	return &AuthMiddleware{
		JwtMaker: jwtMake,
	}
}

func (am *AuthMiddleware) CheckAccessTokenInBlackList() gin.HandlerFunc {
	return func(c *gin.Context) {
		accessToken := c.GetString(access_token)
		if accessToken == "" {
			responses.FailureResponse(c, http.StatusBadRequest, "access token is not provided")
			c.Abort()
			return
		}

		isExists := redis.ExistsKey(fmt.Sprintf("%s%s", global.REDIS_BLACK_LIST, accessToken))
		if isExists {
			responses.FailureResponse(c, http.StatusUnauthorized, "access token is expired")
			c.Abort()
			return
		}

		c.Next()
	}
}

func (am *AuthMiddleware) CheckRefreshTokenInBlackList() gin.HandlerFunc {
	return func(c *gin.Context) {
		refreshToken := c.GetHeader(x_refresh_token)
		if refreshToken == "" {
			responses.FailureResponse(c, http.StatusUnauthorized, "no refresh token provided")
			c.Abort()
			return
		}

		isExists := redis.ExistsKey(fmt.Sprintf("%s%s", global.REDIS_BLACK_LIST, refreshToken))
		if isExists {
			responses.FailureResponse(c, http.StatusUnauthorized, "refresh token is expired")
			c.Abort()
			return
		}

		c.Next()
	}
}

func (am *AuthMiddleware) CheckPermission() gin.HandlerFunc {
	return func(c *gin.Context) {
		accessToken := c.GetString(access_token)
		if accessToken == "" {
			responses.FailureResponse(c, http.StatusBadRequest, "access token is not provided")
			c.Abort()
			return
		}
		// Step 1: Verify the access token
		claims, err := am.JwtMaker.VerifyAccessToken(accessToken)
		if err != nil {
			// Step 2: If access token is expired, attempt to refresh with refresh token
			if err.Error() == jwt.ExpiredTokenErr.Error() {
				// Get the refresh token from request header
				refreshToken := c.GetHeader(x_refresh_token)
				if refreshToken == "" {
					responses.FailureResponse(c, http.StatusUnauthorized, "no refresh token provided")
					c.Abort()
					return
				}
				// Step 3: Verify and refresh access token using refresh token
				newAccessToken, _, refreshErr := am.JwtMaker.RefreshAccessToken(refreshToken)
				if refreshErr != nil {
					responses.FailureResponse(c, http.StatusUnauthorized, fmt.Sprintf("failed to refresh token: %v", refreshErr))
					c.Abort()
					return
				}
				// Return the new access token to the client
				c.Header(x_new_refresh_token, newAccessToken)
				c.Next()
				return
			}
			responses.FailureResponse(c, http.StatusUnauthorized, fmt.Sprintf("%v", err))
			c.Abort()
			return
		}

		c.Set("role", claims.Role)
		c.Set("email", claims.Email)
		c.Next()
	}
}

func (am *AuthMiddleware) GetAccessToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			responses.FailureResponse(c, http.StatusUnauthorized, "unauthorized: no access token provided")
			c.Abort()
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			responses.FailureResponse(c, http.StatusUnauthorized, "invalid Authorization header format")
			c.Abort()
			return
		}

		accessToken := parts[1]

		c.Set(access_token, accessToken)
		c.Next()
	}
}

func (am *AuthMiddleware) GetRefreshToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		var req request.LogoutReq
		if err := c.ShouldBindJSON(&req); err != nil {
			responses.FailureResponse(c, http.StatusBadRequest, "request is invalid")
			c.Abort()
			return
		}

		c.Set(refresh_token, req.RefreshToken)
		c.Next()
	}
}

func (am *AuthMiddleware) DestroyToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		accessToken := c.GetString(access_token)
		if accessToken == "" {
			responses.FailureResponse(c, http.StatusBadRequest, "access token is not provided")
			c.Abort()
			return
		}

		refreshToken := c.GetString(refresh_token)
		if refreshToken == "" {
			responses.FailureResponse(c, http.StatusBadRequest, "refresh token is not provided")
			c.Abort()
			return
		}

		accessClaims, err := am.JwtMaker.VerifyAccessToken(accessToken)
		if err != nil {
			responses.FailureResponse(c, http.StatusInternalServerError, err.Error())
			c.Abort()
			return
		}

		ttl := time.Until(accessClaims.ExpiredAt)
		if ttl > 0 {
			key := fmt.Sprintf("%s%s", global.REDIS_BLACK_LIST, accessToken)
			_ = redis.Save(key, "revoked", int64(ttl.Minutes()))
		}

		refreshClaims, _ := am.JwtMaker.VerifyRefreshToken(refreshToken)
		ttl = time.Until(refreshClaims.ExpiredAt)
		if ttl > 0 {
			key := fmt.Sprintf("%s%s", global.REDIS_BLACK_LIST, refreshToken)
			_ = redis.Save(key, "revoked", int64(ttl.Minutes()))
		}

		c.Set("email", accessClaims.Email)
	}
}
