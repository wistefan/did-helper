package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/wistefan/did-helper/did"
	"github.com/wistefan/did-helper/did/server"
	"go.uber.org/zap"
)

type Config struct {
	KeystorePath     string
	KeystorePassword string
	CertPath         string
	OutputFormat     string
	OutputFile       string
	DidType          string
	KeyType          string
	HostUrl          string
	CertUrl          string
	RunServer        bool
	ServerPort       int
}

func init() {
	zap.ReplaceGlobals(zap.Must(zap.NewDevelopment()))
}

func main() {
	var cfg Config
	var fileContent []byte

	flag.StringVar(&cfg.KeystorePath, "keystorePath", "", "Path to the keystore to be read.")
	flag.StringVar(&cfg.KeystorePassword, "keystorePassword", "", "Password for the keystore.")
	flag.StringVar(&cfg.OutputFormat, "outputFormat", "json", "Output format for the did result file. Can be json, env or json_jwk.")
	flag.StringVar(&cfg.OutputFile, "outputFile", "", "File to write the did, format depends on the requested format. Will not write the file if empty.")
	flag.StringVar(&cfg.DidType, "didType", "key", "Type of the did to generate. did:key and did:jwk are supported.")
	flag.StringVar(&cfg.KeyType, "keyType", "P-256", "Type of the did-key to be created. Supported ED-25519, P-256, P-384.")
	flag.StringVar(&cfg.HostUrl, "hostUrl", "", "Base URL where the DID document will be located, excluding 'did.json'. (e.g., https://example.com/alice for https://example.com/alice/did.json)")
	flag.StringVar(&cfg.CertUrl, "certUrl", "", "URL to retrieve the public certificate. Defaults to 'hostUrl' + /.well-known/tls.crt")
	flag.BoolVar(&cfg.RunServer, "server", true, "Run a server with /did.json and /.well-known/tls.crt endpoints")
	flag.IntVar(&cfg.ServerPort, "port", 8080, "Server port. Default 8080")
	flag.Parse()

	if !cfg.RunServer {
		zap.L().Sugar().Infof("Path to the keystore: %s", cfg.KeystorePath, "Password to be used: %s", cfg.KeystorePassword, "Output file: %s", cfg.OutputFile)
	}

	var resultingDid string
	var err error

	switch cfg.DidType {
	case "key":
		resultingDid, err = did.GetDIDKeyFromECPKCS12(cfg.KeystorePath, cfg.KeystorePassword, cfg.KeyType)
	case "jwk":
		resultingDid, err = did.GetDIDJWKFromKey(cfg.KeystorePath, cfg.KeystorePassword)
	case "web":
		resultingDid, err = did.GetDIDWeb(cfg.HostUrl)
	default:
		zap.L().Sugar().Warnf("Did type %s is not supported.", cfg.DidType)
	}

	if err != nil {
		fmt.Println("Was not able to extract did. Err: ", err)
	} else {
		fmt.Println("Did key is: ", resultingDid)
	}

	switch cfg.OutputFormat {
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
		if cfg.CertUrl == "" {
			cfg.CertUrl = strings.TrimSuffix(cfg.HostUrl, "/") + "/.well-known/tls.crt"
		}
		keySet, err := did.GetJWKFromPKCS12(cfg.KeystorePath, cfg.KeystorePassword, cfg.CertUrl)
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
	if cfg.OutputFile != "" {

		err = os.WriteFile(cfg.OutputFile, fileContent, 0644)
		if err != nil {
			zap.L().Sugar().Warnf("Was not able to write the did-json to %s. Err: %s", cfg.OutputFile, err)
			return
		}
	} else if cfg.RunServer {
		// Error is detected genering the content
		cert, _ := did.GetCert(cfg.KeystorePath, cfg.KeystorePassword)
		server := server.NewDidServer(string(fileContent), string(cert), cfg.ServerPort)
		server.Start()
	} else {
		fmt.Println("Output: ", string(fileContent))
	}
}
