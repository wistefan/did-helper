## Create P-256 Key and Certificate

In order to provide a [did:key of type P-256](https://w3c-ccg.github.io/did-method-key/#p-256), first a key and certificate needs to be created

```shell
# generate the private key - dont get confused about the curve, openssl uses the name `prime256v1` for `secp256r1`(as defined by P-256)
openssl ecparam -name prime256v1 -genkey -noout -out private-key.pem

# generate corresponding public key
openssl ec -in private-key.pem -pubout -out public-key.pem

# create a (self-signed) certificate
openssl req -new -x509 -key private-key.pem -out cert.pem -days 360

# export the keystore
openssl pkcs12 -export -inkey private-key.pem -in cert.pem -out cert.pfx -name the-alias

# check the contents
keytool -v -keystore cert.pfx -list -alias the-alias
```

## Get the did

To generate a did from the generated keystore:

> :warning: Currently, only P-256 keys are supported.

```shell
    wget https://github.com/wistefan/did-helper/releases/download/0.0.2/did-helper
    chmod +x did-helper
    ./did-helper -keystorePath ./example/cert.pfx -keystorePassword=password
``` 

Alternatively, you could use the container:
