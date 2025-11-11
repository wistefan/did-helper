package did

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/trustbloc/kms-go/doc/util/fingerprint"
	"go.uber.org/zap"
	"software.sslmate.com/src/go-pkcs12"
)

func GetDIDKeyFromECPKCS12(path, password, keyType string) (did string, err error) {

	privateKey, _, err := getPrivateKeyFromKeyStore(path, password)
	if err != nil {
		zap.L().Sugar().Warnf("Was not able to decode the keystore %s", path, "error", err)
		return did, err
	}

	switch keyType {
	case "P-256":
		fallthrough
	case "P-384":
		return getECDID(path, keyType, privateKey)
	case "ED-25519":
		return getED25519DID(path, keyType, privateKey)
	default:
		return did, errors.ErrUnsupported
	}
}

func getECDID(path, keyType string, privateKey interface{}) (did string, err error) {
	ecKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		zap.L().Sugar().Warnf("Keystore %s does not contain a valid EC Private Key.", path)
		return did, errors.New("no_ec_private_key")
	}

	var code uint64

	switch keyType {
	case "P-256":
		code = fingerprint.P256PubKeyMultiCodec
	case "P-384":
		code = fingerprint.P384PubKeyMultiCodec
	}
	keyFromDid, _ := fingerprint.CreateDIDKeyByCode(code, elliptic.MarshalCompressed(ecKey.Curve, ecKey.PublicKey.X, ecKey.PublicKey.Y))
	zap.L().Sugar().Infof("Created did %s", keyFromDid)
	return keyFromDid, err

}
func getED25519DID(path, keyType string, privateKey interface{}) (did string, err error) {
	edPrivateKey, ok := privateKey.(ed25519.PrivateKey)
	if !ok {
		zap.L().Sugar().Warnf("Keystore %s does not contain a valid ED.25519 Private Key.", path)
		return did, errors.New("no_ed_private_key")
	}
	pubBytes := edPrivateKey.Public().(ed25519.PublicKey)
	keyFromDid, _ := fingerprint.CreateDIDKeyByCode(fingerprint.ED25519PubKeyMultiCodec, pubBytes)
	zap.L().Sugar().Infof("Created did %s", keyFromDid)
	return keyFromDid, nil
}

func GetDIDJWKFromKey(path string, password string) (did string, err error) {

	jwkKey, err := getKeySetFromKeyStore(path, password)
	if err != nil {
		zap.L().Sugar().Fatalf("failed to create JWK: %v", err)
		return did, err
	}

	publicKey, err := jwkKey.PublicKey()
	if err != nil {
		zap.L().Sugar().Fatalf("failed to get the public key: %v", err)
		return did, err
	}
	jsonKey, err := json.Marshal(publicKey)
	if err != nil {
		zap.L().Sugar().Fatalf("failed to marshal the public key: %v", err)
		return did, err
	}

	encoded := base64.RawStdEncoding.EncodeToString(jsonKey)

	return "did:jwk:" + encoded, err
}

func GetDIDWeb(hostUrl string) (did string, err error) {

	if hostUrl == "" {
		return did, errors.New("`hostUrl` parameter cannot be null when did type is `web`")
	}

	webUrl, err := url.Parse(hostUrl)
	if err != nil {
		zap.L().Sugar().Errorf("'%s' is not a valid url")
		return did, err
	}

	did = "did:web:" + webUrl.Host
	if webUrl.Path != "/" {
		did = did + strings.ReplaceAll(webUrl.Path, "/", ":")
	}
	return did, err
}

func GetJWKFromPKCS12(path string, password string, certPath string) (jwkKey jwk.Key, err error) {

	jwkKey, err = getKeySetFromKeyStore(path, password)
	if err != nil {
		zap.L().Sugar().Fatalf("failed to create JWK: %v", err)
		return jwkKey, err
	}
	jwk.AssignKeyID(jwkKey, jwk.WithThumbprintHash(crypto.SHA256))
	if certPath != "" {
		jwkKey.Set(jwk.X509URLKey, certPath)
	}

	return
}

func getPrivateKeyFromKeyStore(path string, password string) (privateKey interface{}, cert *x509.Certificate, err error) {

	bytes, err := os.ReadFile(path)

	if err != nil {
		zap.L().Sugar().Warnf("Was not able to read the file %s", path, "error", err)
		return privateKey, cert, err
	}

	privateKey, cert, err = pkcs12.Decode(bytes, password)
	if err != nil {
		zap.L().Sugar().Warnf("Was not able to decode the keystore %s", path, "error", err)
		return privateKey, cert, err
	}
	return
}

func getKeySetFromKeyStore(path string, password string) (jwkKey jwk.Key, err error) {

	_, cert, err := getPrivateKeyFromKeyStore(path, password)

	if err != nil {
		zap.L().Sugar().Fatalf("Was not able to read key. Err: %v", err)
		return jwkKey, err

	}
	jwkPrivkey, err := jwk.PublicKeyOf(cert.PublicKey)
	if err != nil {
		zap.L().Sugar().Fatalf("Unable to generate jwk")
		return jwkKey, err
	}
	jwkKey, err = jwkPrivkey.PublicKey()
	return
}
