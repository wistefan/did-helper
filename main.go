package main

import (
	"flag"
	"fmt"

	"github.com/wistefan/did-helper/did"
	"go.uber.org/zap"
)

func init() {
	zap.ReplaceGlobals(zap.Must(zap.NewDevelopment()))
}

func main() {
	var path string
	var password string

	flag.StringVar(&path, "keystorePath", "", "Path to the keystore to be read.")
	flag.StringVar(&password, "keystorePassword", "", "Password for the keystore.")

	flag.Parse()

	zap.L().Sugar().Infof("Path to the keystore: %s", path, "Password to be used: %s", password)

	did, err := did.GetDIDKeyFromECPKCS12(path, password)

	if err != nil {
		fmt.Println("Was not able to extract did. Err: ", err)
	} else {
		fmt.Println("Did key is: ", did)
	}
}
