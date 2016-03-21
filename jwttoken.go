package tokenauth

import (
	"time"

	"github.com/dgrijalva/jwt-go"
)

type JwtToken struct {
	tokenKey []byte
	jwt.Token
}

func (t *JwtToken) Claims(key string) interface{} {
	return t.Token.Claims[key]
}

func (t *JwtToken) SetClaim(key string, value interface{}) ClaimSetter {
	t.Token.Claims[key] = value
	return t
}

func (t *JwtToken) Expiry() time.Time {
	expt := t.Claims("exp")
	var exp time.Time
	switch t := expt.(type) {
	case float64:
		exp = time.Unix(int64(t), 0)
	case int64:
		exp = time.Unix(t, 0)
	default:
		exp = time.Now()
	}
	return exp
}

func (t *JwtToken) IsExpired() bool {
	exp := t.Expiry()
	return time.Now().After(exp)
}

func (t *JwtToken) String() string {
	tokenStr, _ := t.Token.SignedString(t.tokenKey)
	return tokenStr
}
