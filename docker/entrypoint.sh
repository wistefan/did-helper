#!/bin/bash

cd /cert


case "$KEY_TYPE_TO_GENERATE" in
  EC)
    openssl ecparam -name prime256v1 -genkey -noout -out private-key.pem
    openssl ec -in private-key.pem -pubout -out public-key.pem
    ;;
  RSA)
    openssl genrsa -out private-key.pem 4096
    openssl rsa -in private-key.pem -pubout -out public-key.pem
    ;;
  *)
    echo "Unsupported KEY_TYPE: $KEY_TYPE_TO_GENERATE. Use 'EC' or 'RSA'."
    exit 1
    ;;
esac

openssl req -new -x509 -key private-key.pem -out cert.pem -days 360 -subj "/C=${COUNTRY}/ST=${STATE}/L=${LOCALITY}/O=${ORGANIZATION}/CN=${COMMON_NAME}"
openssl pkcs12 -export -inkey private-key.pem -in cert.pem -out cert.pfx -name ${KEY_ALIAS} -password pass:${STORE_PASS}


cd /temp
/did-helper/did-helper -keystorePath /cert/cert.pfx -keystorePassword ${STORE_PASS} -outputFile ${OUTPUT_FILE} -outputFormat ${OUTPUT_FORMAT} -didType ${DID_TYPE}