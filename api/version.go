package api

import "net/http"

const VERSION = "0.3"

func Version(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(VERSION))
}
