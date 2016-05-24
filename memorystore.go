package tokenauth

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"
)

type MemoryTokenStore struct {
	tokens   map[string]*MemoryToken
	idTokens map[string]*MemoryToken
	salt     string
}

func (s *MemoryTokenStore) generateToken(id string) []byte {
	hash := sha256.New()
	now := time.Now()
	timeStr := now.Format(time.ANSIC)
	hash.Write([]byte(timeStr))
	hash.Write([]byte(id))
	hash.Write([]byte(s.salt))
	return hash.Sum(nil)
}

func (s *MemoryTokenStore) NewToken(id interface{}, duration int64) *MemoryToken {
	strId := id.(string)
	bToken := s.generateToken(strId)
	strToken := base64.URLEncoding.EncodeToString(bToken)
	t := &MemoryToken{
		ExpireAt: time.Now().Add(time.Second * time.Duration(duration)),
		Token:    strToken,
		Id:       strId,
	}
	oldT, ok := s.idTokens[strId]
	if ok {
		delete(s.tokens, oldT.Token)
	}
	s.tokens[strToken] = t
	s.idTokens[strId] = t
	return t
}

func (s *MemoryTokenStore) RemoveToken(strToken string) {
	delete(s.tokens, strToken)
}

func NewMemoryTokenStore(salt string) *MemoryTokenStore {
	return &MemoryTokenStore{
		salt:     salt,
		tokens:   make(map[string]*MemoryToken),
		idTokens: make(map[string]*MemoryToken),
	}

}

func (s *MemoryTokenStore) CheckToken(strToken string) (Token, error) {
	t, ok := s.tokens[strToken]
	if !ok {
		return nil, errors.New("No this Token")
	}
	if t.ExpireAt.Before(time.Now()) {
		delete(s.tokens, strToken)
		return nil, errors.New("Token expired")
	}
	return t, nil
}
