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
	if claims, ok := t.Token.Claims.(jwt.MapClaims); ok && t.Token.Valid {
		return claims[key]
	}
	return nil
}

func (t *JwtToken) SetClaim(key string, value interface{}) ClaimSetter {
	if claims, ok := t.Token.Claims.(jwt.MapClaims); ok && t.Token.Valid {
		claims[key] = value
	}
	return t
}

func (t *JwtToken) Expiry() time.Time {
	var exp time.Time = time.Now()
	if claims, ok := t.Token.Claims.(jwt.MapClaims); ok && t.Token.Valid {
		expt := claims["exp"]
		switch t := expt.(type) {
		case float64:
			exp = time.Unix(int64(t), 0)
		case int64:
			exp = time.Unix(t, 0)
		default:
			exp = time.Now()
		}
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
