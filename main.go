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
	var outputFormat string
	var didType string
	var keyType string

	flag.StringVar(&path, "keystorePath", "", "Path to the keystore to be read.")
	flag.StringVar(&password, "keystorePassword", "", "Password for the keystore.")
	flag.StringVar(&outputFormat, "outputFormat", "json", "Output format for the did result file. Can be json or env.")
	flag.StringVar(&outputFile, "outputFile", "", "File to write the did, format depends on the requested format. Will not write the file if empty.")
	flag.StringVar(&didType, "didType", "key", "Type of the did to generate. did:key and did:jwk are supported.")
	flag.StringVar(&keyType, "keyType", "P-256", "Type of the did-key to be created. Supported ED-25519, P-256, P-384.")

	flag.Parse()

	zap.L().Sugar().Infof("Path to the keystore: %s", path, "Password to be used: %s", password, "Output file: %s", outputFile)

	var resultingDid string
	var err error

	switch didType {
	case "key":
		resultingDid, err = did.GetDIDKeyFromECPKCS12(path, password, keyType)
	case "jwk":
		resultingDid, err = did.GetDIDJWKFromKey(path, password)
	default:
		zap.L().Sugar().Warnf("Did type %s is not supported.", didType)
	}

	if err != nil {
		fmt.Println("Was not able to extract did. Err: ", err)
	} else {
		fmt.Println("Did key is: ", resultingDid)
	}

	if outputFile != "" && outputFormat == "json" {
		didJson := Did{Context: []string{"https://www.w3.org/ns/did/v1"}, Id: resultingDid}
		jsonFileContent, err := json.Marshal(didJson)
		if err != nil {
			zap.L().Sugar().Warnf("Was not able to marshal the did-json. Err: %s", err)
		}
		err = os.WriteFile(outputFile, jsonFileContent, 0644)
		if err != nil {
			zap.L().Sugar().Warnf("Was not able to write the did-json to %s. Err: %s", outputFile, err)
		}
	} else if outputFile != "" && outputFormat == "env" {
		envContent := "DID=" + resultingDid
		err = os.WriteFile(outputFile, []byte(envContent), 0644)
		if err != nil {
			zap.L().Sugar().Warnf("Was not able to write the did-env to %s. Err: %s", outputFile, err)
		}
	}
}

type Did struct {
	Context []string `json:"issuerDid,omitempty"`
	Id      string   `json:"id"`
}
