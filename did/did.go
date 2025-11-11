package did

import "github.com/lestrrat-go/jwx/v3/jwk"

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
