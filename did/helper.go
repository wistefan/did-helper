package did

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/trustbloc/kms-go/doc/util/fingerprint"
	"go.uber.org/zap"
	"software.sslmate.com/src/go-pkcs12"
)

func GetDIDKeyFromECPKCS12(path, password string) (did string, err error) {

	bytes, err := os.ReadFile(path)

	if err != nil {
		zap.L().Sugar().Warnf("Was not able to read the file %s", path, "error", err)
		return did, err
	}

	privateKey, _, err := pkcs12.Decode(bytes, password)
	if err != nil {
		zap.L().Sugar().Warnf("Was not able to decode the keystore %s", path, "error", err)
		return did, err
	}

	ecKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		zap.L().Sugar().Warnf("Keystore %s does not contain a valid EC Private Key.", path)
		return did, errors.New("no_ec_private_key")
	}
	keyFromDid, _ := fingerprint.CreateDIDKeyByCode(fingerprint.P256PubKeyMultiCodec, elliptic.MarshalCompressed(ecKey.Curve, ecKey.PublicKey.X, ecKey.PublicKey.Y))
	zap.L().Sugar().Infof("Created did %s", keyFromDid)
	return keyFromDid, err
}

func GetDIDJWKFromKey(path, password string) (did string, err error) {
	bytes, err := os.ReadFile(path)

	if err != nil {
		zap.L().Sugar().Warnf("Was not able to read the file %s", path, "error", err)
		return did, err
	}

	privateKey, _, err := pkcs12.Decode(bytes, password)

	if err != nil {
		zap.L().Sugar().Fatalf("Was not able to read key. Err: %v", err)
		return did, err

	}

	// Create a JWK from the key
	jwkKey, err := jwk.Import(privateKey)
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
