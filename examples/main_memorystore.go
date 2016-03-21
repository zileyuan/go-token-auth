package main

import (
	"fmt"
	"net/http"

	"git.lichengsoft.com/lichengsoft/go-token-auth"
)

func main() {
	mux := http.NewServeMux()
	memStore := tokenauth.NewMemoryTokenStore("my_service_key")
	tokenAuth := tokenauth.NewTokenAuth(memStore)

	mux.HandleFunc("/login", func(w http.ResponseWriter, req *http.Request) {
		t := memStore.NewToken("user1", 600)
		fmt.Fprintf(w, "hi User1, your token is %s", t)
	})

	mux.HandleFunc("/restricted", func(w http.ResponseWriter, req *http.Request) {
		token, _ := tokenAuth.Authenticate(req.URL.Query().Get("token"))
		fmt.Fprintf(w, "hi %s", token.Claims("id").(string))
	})

	fmt.Println("listening at :3000")
	http.ListenAndServe(":3000", mux)
}
