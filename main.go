package main

import (
	"cloak/api"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/akamensky/argparse"
)

func main() {
	parser := argparse.NewParser("cloak", "generate secure stagers")

	lhost := parser.String("l", "lhost", &argparse.Options{Required: false, Default: "127.0.0.1", Help: "host for Cloak to listen on"})
	lport := parser.Int("p", "lport", &argparse.Options{Required: false, Default: 8080, Help: "port for Cloak to listen on"})

	if err := parser.Parse(os.Args); err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()

	// static handler
	mux.Handle("/", http.FileServer(http.Dir("./static")))

	// api handlers
	mux.Handle("/api/version", http.HandlerFunc(api.Version))   // get cloak version
	mux.Handle("/api/f2j", http.HandlerFunc(api.FormToJson))    // convert form data to json data
	mux.Handle("/api/generate", http.HandlerFunc(api.Generate)) // endpoint for actual payload generation

	log.Printf("Starting Cloak Server on http://%s:%d\n", *lhost, *lport)
	http.ListenAndServe(fmt.Sprintf("%s:%d", *lhost, *lport), mux)
}
