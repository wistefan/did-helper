#!/bin/bash

cd /cert

case "$KEY_TYPE_TO_GENERATE" in
  EC)
    case "$KEY_TYPE" in
      P-256)
        echo "Generating EC P-256 key pair..."
        openssl ecparam -name prime256v1 -genkey -noout -out private-key.pem
        openssl ec -in private-key.pem -pubout -out public-key.pem
        ;;
      P-384)
        echo "Generating EC P-384 key pair..."
        openssl ecparam -name secp384r1 -genkey -noout -out private-key.pem
        openssl ec -in private-key.pem -pubout -out public-key.pem
        ;;
      *)
        echo "Unsupported EC curve: $EC_CURVE. Use P-256 or P-384."
        exit 1
        ;;
    esac
    ;;
  ED-25519)
    echo "Generating Ed25519 key pair..."
    openssl genpkey -algorithm Ed25519 -out private-key.pem
    openssl pkey -in private-key.pem -pubout -out public-key.pem
    ;;
  RSA)
    echo "Generating RSA 4096-bit key pair..."
    openssl genrsa -out private-key.pem 4096
    openssl rsa -in private-key.pem -pubout -out public-key.pem
    ;;
  *)
    echo "Unsupported KEY_TYPE: $KEY_TYPE_TO_GENERATE. Use 'EC', 'ED25519' or 'RSA'."
    exit 1
    ;;
esac

openssl req -new -x509 -key private-key.pem -out cert.pem -days 360 -subj "/C=${COUNTRY}/ST=${STATE}/L=${LOCALITY}/O=${ORGANIZATION}/CN=${COMMON_NAME}"
openssl pkcs12 -export -inkey private-key.pem -in cert.pem -out cert.pfx -name ${KEY_ALIAS} -password pass:${STORE_PASS}


cd /temp
/did-helper/did-helper -keystorePath /cert/cert.pfx -keystorePassword ${STORE_PASS} -outputFile ${OUTPUT_FILE} -outputFormat ${OUTPUT_FORMAT} -didType ${DID_TYPE} -keyType ${KEY_TYPE}