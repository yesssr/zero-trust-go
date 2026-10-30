package lib

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	AccessTokenDuration  = 10 * time.Minute
	TokenIssuer          = "zero-trust-go"
	ServiceTokenDuration = 5 * time.Minute
	ServiceTokenType     = "service"
)

type AccessClaims struct {
	Role string `json:"role"`
	jwt.RegisteredClaims
}

type ServiceClaims struct {
	Role      string `json:"role"`
	TokenType string `json:"token_type"`
	jwt.RegisteredClaims
}

func GenerateServiceToken(clientID, secret string) (string, error) {
	now := time.Now()

	claims := ServiceClaims{
		Role:      "service",
		TokenType: ServiceTokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    TokenIssuer,
			Subject:   clientID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ServiceTokenDuration)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedToken, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func ValidateServiceToken(tokenString, secret string) (*ServiceClaims, error) {
	claims := &ServiceClaims{}

	token, err := jwt.ParseWithClaims(
		tokenString,
		claims,
		func(t *jwt.Token) (any, error) {
			if t.Method != jwt.SigningMethodHS256 {
				return nil, errors.New("unexpected signing method")
			}

			return []byte(secret), nil
		},
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithIssuer(TokenIssuer),
		jwt.WithExpirationRequired(),
	)

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("invalid service token")
	}

	if claims.Role != "service" || claims.TokenType != ServiceTokenType {
		return nil, errors.New("invalid service token type")
	}

	if claims.Subject == "" {
		return nil, errors.New("missing service identity")
	}

	return claims, nil
}

func GenerateAccessToken(
	userID int64,
	role string,
	secret string,
) (string, error) {
	if userID == 0 {
		return "", fmt.Errorf("invalid role")
	}

	switch role {
	case "admin", "lecturer", "student":
	default:
		return "", fmt.Errorf("invalid role")
	}

	if secret == "" {
		return "", fmt.Errorf("JWT secret is required")
	}

	now := time.Now()

	claims := AccessClaims{
		Role: role,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    TokenIssuer,
			Subject:   strconv.FormatInt(userID, 10),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(AccessTokenDuration)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedToken, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", fmt.Errorf("sign access token: %w", err)
	}

	return signedToken, nil
}

func ValidateAccessToken(
	tokenString string,
	secret string,
) (*AccessClaims, error) {
	if tokenString == "" || secret == "" {
		return nil, fmt.Errorf("token and secret are required")
	}

	claims := &AccessClaims{}

	token, err := jwt.ParseWithClaims(
		tokenString,
		claims,
		func(token *jwt.Token) (any, error) {
			return []byte(secret), nil
		},
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithIssuer(TokenIssuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("parse access token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid access token")
	}

	if claims.Subject == "" {
		return nil, fmt.Errorf("token subject is missing")
	}

	if _, err := strconv.ParseInt(claims.Subject, 10, 64); err != nil {
		return nil, fmt.Errorf("invalid token subject")
	}

	switch claims.Role {
	case "admin", "lecturer", "student":
	default:
		return nil, fmt.Errorf("invalid token role")
	}

	return claims, nil
}
