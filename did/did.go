package did

import (
	"crypto/x509"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

type Did struct {
	Context            []string             `json:"@context,omitempty"`
	IssuerDid          []string             `json:"issuerDid,omitempty"`
	Id                 string               `json:"id"`
	VerificationMethod []VerificationMethod `json:"verificationMethod,omitempty"`
}

type VerificationMethod struct {
	Id           string  `json:"id"`
	Type         string  `json:"type"`
	Controller   string  `json:"controller"`
	PublicKeyJwk jwk.Key `json:"publicKeyJwk,omitempty"`
}

type Config struct {
	KeystorePath     string
	KeystorePassword string
	CertPath         string
	KeyPath          string
	OutputFormat     string
	OutputFile       string
	DidType          string
	KeyType          string
	HostUrl          string
	CertUrl          string
	RunServer        bool
	ServerPort       int
	Certificates     Certificates
}

type Certificates struct {
	PublicKey  *x509.Certificate
	PrivateKey interface{}
}
