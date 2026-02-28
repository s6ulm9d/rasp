#!/usr/bin/env bash
set -e

mkdir -p certs
cd certs

# Generate CA
openssl genrsa -out ca.key 2048
openssl req -new -x509 -days 365 -key ca.key -subj "/C=US/ST=CA/L=SF/O=ShieldRASP/CN=ShieldRASP Root CA" -out ca.crt

# Generate Server Cert
openssl req -newkey rsa:2048 -nodes -keyout server.key -subj "/C=US/ST=CA/L=SF/O=ShieldRASP/CN=localhost" -out server.csr
openssl x509 -req -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1") -days 365 -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt

echo "Generated self-signed TLS certificates for local environment."
