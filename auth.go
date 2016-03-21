package tokenauth

import (
	"errors"
	"fmt"
)

type TokenAuth struct {
	store TokenStore
}

type TokenStore interface {
	CheckToken(token string) (Token, error)
}

type Token interface {
	IsExpired() bool
	fmt.Stringer
	ClaimGetter
}

type ClaimSetter interface {
	SetClaim(string, interface{}) ClaimSetter
}

type ClaimGetter interface {
	Claims(string) interface{}
}

func NewTokenAuth(store TokenStore) *TokenAuth {
	t := &TokenAuth{
		store: store,
	}
	return t
}

func (t *TokenAuth) Authenticate(tokenStr string) (Token, error) {
	if tokenStr == "" {
		return nil, errors.New("token required")
	}
	token, err := t.store.CheckToken(tokenStr)
	if err != nil {
		return nil, errors.New("Invalid token")
	}
	return token, nil
}
