#!/bin/bash

cd /cert

openssl ecparam -name prime256v1 -genkey -noout -out private-key.pem
openssl ec -in private-key.pem -pubout -out public-key.pem
openssl req -new -x509 -key private-key.pem -out cert.pem -days 360 -subj "/C=${COUNTRY}/ST=${STATE}/L=${LOCALITY}/O=${ORGANIZATION}/CN=${COMMON_NAME}"
openssl pkcs12 -export -inkey private-key.pem -in cert.pem -out cert.pfx -name ${KEY_ALIAS} -password pass:${STORE_PASS}

cd /temp
/did-helper/did-helper -keystorePath /cert/cert.pfx -keystorePassword=${STORE_PASS} -outputFile /cert/did.json