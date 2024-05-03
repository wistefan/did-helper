package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/wistefan/did-helper/did"
	"go.uber.org/zap"
)

func init() {
	zap.ReplaceGlobals(zap.Must(zap.NewDevelopment()))
}

func main() {
	var path string
	var password string
	var outputFile string

	flag.StringVar(&path, "keystorePath", "", "Path to the keystore to be read.")
	flag.StringVar(&password, "keystorePassword", "", "Password for the keystore.")
	flag.StringVar(&outputFile, "outputFile", "", "File to write the did.json. Will not write the file if empty.")

	flag.Parse()

	zap.L().Sugar().Infof("Path to the keystore: %s", path, "Password to be used: %s", password, "Output file: %s", outputFile)

	did, err := did.GetDIDKeyFromECPKCS12(path, password)

	if err != nil {
		fmt.Println("Was not able to extract did. Err: ", err)
	} else {
		fmt.Println("Did key is: ", did)
	}

	if outputFile != "" {
		didJson := Did{Context: []string{"https://www.w3.org/ns/did/v1"}, Id: did}
		jsonFileContent, err := json.Marshal(didJson)
		if err != nil {
			zap.L().Sugar().Warnf("Was not able to marshal the did-json. Err: %s", err)
		}
		err = os.WriteFile(outputFile, jsonFileContent, 0644)
		if err != nil {
			zap.L().Sugar().Warnf("Was not able to write the did-json to %s. Err: %s", outputFile, err)
		}
	}
}

type Did struct {
	Context []string `json:"issuerDid,omitempty"`
	Id      string   `json:"id"`
}
