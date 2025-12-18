#!/bin/bash

# Generate standard X.509 certificates for DTLS (not PQC, but will show real encryption)

echo "Generating standard X.509 certificates for encrypted DTLS demo..."
mkdir -p test_certs
cd test_certs

# Generate CA
openssl req -x509 -newkey rsa:2048 -keyout ca-key.pem -out ca-cert.pem -days 365 -nodes -subj "/CN=Test CA"

# Generate Server cert
openssl req -newkey rsa:2048 -keyout server-key.pem -out server-req.pem -nodes -subj "/CN=localhost"
openssl x509 -req -in server-req.pem -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out server-cert.pem -days 365

# Convert to DER format
openssl x509 -in ca-cert.pem -outform DER -out ca-cert.der
openssl x509 -in server-cert.pem -outform DER -out server-cert.der
openssl rsa -in server-key.pem -outform DER -out server-key.der

cd ..

echo "✓ Certificates generated in test_certs/"
ls -lh test_certs/*.der
