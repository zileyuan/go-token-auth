package tokenauth

import (
	"testing"
)

func TestSignature(t *testing.T) {
	sign, err := Signature("lichengsoftcrypt", "skdfjlieafwqeufhewfilewve", "2016-03-15T15:04:05Z", "600", "HMAC-SHA256", "1.0")
	if err != nil {
		t.Error(err.Error())
	}
	t.Log(sign)
}

func TestAuthSignature(t *testing.T) {
	ok := AuthSignature("lichengsoftcrypt", "skdfjlieafwqeufhewfilewve", "2016-03-15T15:04:05Z", "600", "HMAC-SHA256", "1.0", "7rTSWY+pPn2njS5rTqDPPDa+jnDkN1g+ld9yUETlRIfx3Jv9em6oPAatMujcj3gm2PpgTyqVVEB2pU1XhnZoUzDLVq721X8m3q/cpQ+mDNK5Wab77UcuNSbJ/YVCZG5LIG80jPKTBuAw3uAx+I5r5p27tZWliGs=")
	if ok != true {
		t.Error("Auth Fail")
	}
}
