package api

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"

	_ "github.com/glebarez/go-sqlite"
)

type dbPayload struct {
	Id   int
	Name string
	Type string
	Time int
}

func Download(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte("only GET method allowed"))

		return
	}

	params, _ := url.ParseQuery(r.URL.RawQuery)
	id := params.Get("id")

	// get data from db
	db, err := sql.Open("sqlite", "./cloak.db")
	if err != nil {
		log.Fatal(err)
	}

	iid, err := strconv.Atoi(id)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))

		return
	}
	res, err := db.Query("SELECT * FROM Payloads WHERE ID = $1", iid)
	if err != nil {
		log.Fatal(err)
	}

	var p dbPayload
	for res.Next() {
		err = res.Scan(&p.Id, &p.Name, &p.Type, &p.Time)
		if err != nil {
			log.Fatal(err)
		}
	}

	// read the file based on id
	payload, err := os.ReadFile(fmt.Sprintf("./bins/%s_%d.%s", p.Name, p.Time, p.Type))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))

		return
	}

	// send payload
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.%s", p.Name, p.Type))
	w.Header().Set("Content-Type", "application/octet-stream")

	w.Write(payload)
}
