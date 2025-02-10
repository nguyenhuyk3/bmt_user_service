package middlewares

import (
	"fmt"
	"net/http"
	"strings"
	"user_service/internal/responses"
	"user_service/utils/token/jwt"

	"github.com/gin-gonic/gin"
)

type AuthMiddleware struct {
	JwtMaker jwt.IMaker
}

func NewAuthMiddleware(jwtMake jwt.IMaker) *AuthMiddleware {
	return &AuthMiddleware{
		JwtMaker: jwtMake,
	}
}

func (am *AuthMiddleware) CheckPermission() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			responses.FailureResponse(c, http.StatusUnauthorized, "unauthorized: no token provided")
			c.Abort()

			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			responses.FailureResponse(c, http.StatusUnauthorized, "invalid Authorization header format")
			c.Abort()

			return
		}

		token := parts[1]
		// Step 1: Verify the access token
		claims, err := am.JwtMaker.VerifyAccessToken(token)
		if err != nil {
			// Step 2: If access token is expired, attempt to refresh with refresh token
			if err.Error() == jwt.ExpiredTokenErr.Error() {
				// Get the refresh token from request header
				refreshToken := c.GetHeader("X-Refresh-Token")
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
				c.Header("X-New-Access-Token", newAccessToken)
				// Optionally set the new access token in the context for downstream handlers
				c.Set("access_token", newAccessToken)
				c.Next()

				return
			}
			// Handle other errors (invalid token, etc.)
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
			responses.FailureResponse(c, http.StatusUnauthorized, "unauthorized: no token provided")
			c.Abort()

			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			responses.FailureResponse(c, http.StatusUnauthorized, "invalid Authorization header format")
			c.Abort()

			return
		}

		token := parts[1]

		c.Set("token", token)
		c.Next()
	}
}
