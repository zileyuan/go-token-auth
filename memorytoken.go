package tokenauth

import (
	"time"
)

type MemoryToken struct {
	ExpireAt time.Time
	Token    string
	Id       string
}

func (t *MemoryToken) IsExpired() bool {
	return time.Now().After(t.ExpireAt)
}

func (t *MemoryToken) String() string {
	return t.Token
}

/* lookup 'exp' or 'id' */
func (t *MemoryToken) Claims(key string) interface{} {
	switch key {
	case "exp":
		return t.ExpireAt
	case "id":
		return t.Id
	default:
		return nil
	}
}
