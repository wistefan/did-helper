package did

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"os"

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
