package tokenauth

import (
	"errors"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type JwtStore struct {
	tokenKey []byte
}

func (s *JwtStore) NewToken(id interface{}, duration int64) *JwtToken {
	token := jwt.New(jwt.GetSigningMethod("HS256"))
	token.Claims["jti"] = id
	token.Claims["exp"] = time.Now().Add(time.Second * time.Duration(duration)).Unix()
	t := &JwtToken{
		tokenKey: s.tokenKey,
		Token:    *token,
	}
	return t
}

func (s *JwtStore) CheckToken(token string) (Token, error) {
	t, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return s.tokenKey, nil
	})
	if err != nil {
		return nil, err
	}
	jtoken := &JwtToken{s.tokenKey, *t}
	if jtoken.IsExpired() {
		return nil, errors.New("Token expired")
	}
	return jtoken, nil
}

func NewJwtStore(tokenKey string) *JwtStore {
	return &JwtStore{
		[]byte(tokenKey),
	}
}
