package nosurf

import (
	"net/http"
)

func dummyGet() *http.Request {
	req, err := http.NewRequest("GET", "http://dum.my/", nil)
	if err != nil {
		panic(err)
	}
	return req
}

func succHand(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(200)
	w.Write([]byte("success"))
}
