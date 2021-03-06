# ROOT CA

openssl ecparam -name prime256v1 -genkey -noout -outform PEM -out temp.ca.key.pem

openssl pkcs8 -topk8 -nocrypt -in ca.key.pem -out ec2.pem

openssl req -config openssl.cnf -key ca.key.pem -new -x509 -days 7500 -sha256 -extensions v3_ca -out ca.cert.pem -subj "/C=US/ST=California/L=San Francisco/CN=broadridge.com"

openssl x509 -noout -text -in ca.cert.pem | grep -A1 "Subject Key Identifier"  | awk  -F 'X509v3 Subject Key Identifier:' '{print $1}' | sed 's/://g' 

# INTERMEDIATE CA
openssl ecparam -name prime256v1 -genkey -noout  -out cacerts.key.pem
openssl req -new -config openssl.cnf -extensions v3_intermediate_ca -x509 -key cacerts.key.pem -out  cacerts.csr.pem -subj "openssl req -config openssl.cnf -key ca.key.pem -new -x509 -days 7500 -sha256 -extensions v3_ca -out ca.cert.pem -subj "/C=US/ST=California/L=San Francisco/CN=broadridge.com"/CN=bcoe"
openssl x509 -days 1000 -in cacerts.csr.pem -CA ca.cert.pem -CAkey ca.key.pem -out cacerts.cert.pem

openssl ecparam -name prime256v1 -genkey -noout  -out tlscacerts.key.pem
openssl req -new -config openssl.cnf -extensions v3_intermediate_ca -x509 -key cacerts.key.pem -out  cacerts.csr.pem -subj "openssl req -config openssl.cnf -key ca.key.pem -new -x509 -days 7500 -sha256 -extensions v3_ca -out ca.cert.pem -subj "/C=US/ST=California/L=San Francisco/CN=broadridge.com"/CN=bcoe"
openssl x509 -days 1000 -in cacerts.csr.pem -CA ca.cert.pem -CAkey ca.key.pem -out cacerts.cert.pem

openssl x509 -days 1000 -in intermediate/csr/intermediate.csr.pem -CA ca.cert.pem -CAkey ca.key.pem -out intermediate/certs/intermediate.cert.pem 

openssl req -new -key intermediate/private/intermediate.key.pem -out  intermediate/csr/intermediate.csr.pem -subj "/CN=bcoe"

openssl ca -config openssl.cnf -days 3600 -extensions v3_intermediate_ca -notext -md sha256  -in intermediate/csr/intermediate.csr.pem -out intermediate/certs/intermediate.cert.pem -subj "/CN=bcoe.com"


./generate.sh ca.cert.pem ca.key.pem openssl_template.cnf config_template.yaml

openssl x509 -req -days 365 -in ca.cert.pem -signkey ca.key.pem -sha256 -out server.crt

openssl ecparam -genkey -name prime256v1 -noout -out key.pem 
openssl pkcs8 -topk8 -nocrypt -in key.pem -out ca.key.pem
openssl req -new -sha256 -config openssl.cnf -extensions v3_ca  -key ca.key.pem -out csr.csr -subj "/C=US/ST=California/L=San Francisco/CN=broadridge.com"
openssl req -x509 -sha256 -days 365 -key key.pem -in csr.csr -out certificate.pem 

