package main

import (
	"cloak-ui/api"
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/akamensky/argparse"
	_ "github.com/glebarez/go-sqlite"
)

type payload struct {
	Id   string
	Name string
	Type string
	Time string
}

type payloadsPage struct {
	Payload []payload
}

type dbPayload struct {
	Id   int
	Name string
	Type string
	Time int
}

func index(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("./static/index.html"))

	// read db
	db, err := sql.Open("sqlite", "./cloak.db")
	if err != nil {
		log.Fatal(err)
	}

	res, err := db.Query("SELECT * FROM Payloads")
	if err != nil {
		log.Fatal(err)
	}

	var payloads []dbPayload
	for res.Next() {
		var p dbPayload
		err = res.Scan(&p.Id, &p.Name, &p.Type, &p.Time)
		if err != nil {
			log.Fatal(err)
		}

		payloads = append(payloads, p)
	}

	var tmplPayloads []payload
	for _, p := range payloads {
		var py payload

		py.Id = strconv.Itoa(p.Id)
		py.Name = p.Name
		py.Type = p.Type
		py.Time = time.Unix(int64(p.Time), 0).Format(time.RFC1123)

		tmplPayloads = append(tmplPayloads, py)
	}

	data := payloadsPage{
		Payload: tmplPayloads,
	}

	tmpl.Execute(w, data)
}

func main() {
	parser := argparse.NewParser("cloak", "generate secure stagers")

	lhost := parser.String("l", "lhost", &argparse.Options{Required: false, Default: "0.0.0.0", Help: "host for Cloak to listen on"})
	lport := parser.Int("p", "lport", &argparse.Options{Required: false, Default: 8080, Help: "port for Cloak to listen on"})

	if err := parser.Parse(os.Args); err != nil {
		log.Fatal(err)
	}

	// create database
	db, err := sql.Open("sqlite", "./cloak.db")
	if err != nil {
		log.Fatal(err)
	}

	// create payloads table
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS Payloads (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME STRING NOT NULL, TYPE STRING NOT NULL, GENERATED INTEGER NOT NULL)")
	if err != nil {
		log.Fatal(err)
	}
	db.Close()

	mux := http.NewServeMux()

	// static handler
	mux.Handle("/", http.FileServer(http.Dir("./static")))
	mux.HandleFunc("/cloak", index)

	// api handlers
	mux.Handle("/api/version", http.HandlerFunc(api.Version))   // get cloak version
	mux.Handle("/api/f2j", http.HandlerFunc(api.FormToJson))    // convert form data to json data
	mux.Handle("/api/generate", http.HandlerFunc(api.Generate)) // endpoint for actual payload generation
	mux.Handle("/api/download", http.HandlerFunc(api.Download)) // download previously generated payloads

	log.Printf("Starting Cloak Server on http://%s:%d/cloak\n", *lhost, *lport)
	http.ListenAndServe(fmt.Sprintf("%s:%d", *lhost, *lport), mux)
}
