package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

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
	var hostUrl string
	var fileContent []byte
	var certUrl string

	flag.StringVar(&path, "keystorePath", "", "Path to the keystore to be read.")
	flag.StringVar(&password, "keystorePassword", "", "Password for the keystore.")
	flag.StringVar(&outputFormat, "outputFormat", "json", "Output format for the did result file. Can be json, env or json_jwk.")
	flag.StringVar(&outputFile, "outputFile", "", "File to write the did, format depends on the requested format. Will not write the file if empty.")
	flag.StringVar(&didType, "didType", "key", "Type of the did to generate. did:key and did:jwk are supported.")
	flag.StringVar(&keyType, "keyType", "P-256", "Type of the did-key to be created. Supported ED-25519, P-256, P-384.")
	flag.StringVar(&hostUrl, "hostUrl", "", "Base URL where the DID document will be located, excluding 'did.json'. (e.g., https://example.com/alice for https://example.com/alice/did.json)")
	flag.StringVar(&certUrl, "certUrl", "", "URL to retrieve the public certificate. Default is 'hostUrl' + /.well-known/tls.crt")
	flag.Parse()

	zap.L().Sugar().Infof("Path to the keystore: %s", path, "Password to be used: %s", password, "Output file: %s", outputFile)

	var resultingDid string
	var err error

	switch didType {
	case "key":
		resultingDid, err = did.GetDIDKeyFromECPKCS12(path, password, keyType)
	case "jwk":
		resultingDid, err = did.GetDIDJWKFromKey(path, password)
	case "web":
		resultingDid, err = did.GetDIDWeb(hostUrl)
	default:
		zap.L().Sugar().Warnf("Did type %s is not supported.", didType)
	}

	if err != nil {
		fmt.Println("Was not able to extract did. Err: ", err)
	} else {
		fmt.Println("Did key is: ", resultingDid)
	}

	switch outputFormat {
	case "json":
		didJson := did.Did{IssuerDid: []string{"https://www.w3.org/ns/did/v1"}, Id: resultingDid}
		fileContent, err = json.Marshal(didJson)
		if err != nil {
			zap.L().Sugar().Warnf("Was not able to marshal the did-json. Err: %s", err)
			return
		}
	case "env":
		fileContent = ([]byte("DID=" + resultingDid))
	case "json_jwk":
		if certUrl == "" {
			certUrl = strings.Replace(hostUrl+"/.well-known/tls.crt", "//", "/", 1)
		}
		keySet, err := did.GetJWKFromPKCS12(path, password, certUrl)
		if err != nil {
			zap.L().Sugar().Warnf("Error generating keyset. Err: %s", err)
			return
		}
		verificationMethod := did.VerificationMethod{Id: resultingDid, Type: "JsonWebKey2020", Controller: resultingDid, PublicKeyJwk: keySet}
		didJson := did.Did{IssuerDid: []string{"https://www.w3.org/ns/did/v1"}, Id: resultingDid, VerificationMethod: []did.VerificationMethod{verificationMethod}}
		fileContent, err = json.MarshalIndent(didJson, "", "  ")
		if err != nil {
			zap.L().Sugar().Warnf("Error printing keyset")
			return
		}
	}
	if outputFile != "" {

		err = os.WriteFile(outputFile, fileContent, 0644)
		if err != nil {
			zap.L().Sugar().Warnf("Was not able to write the did-json to %s. Err: %s", outputFile, err)
			return
		}
	} else {
		zap.L().Sugar().Infof("Result: %s", fileContent)
	}

}
