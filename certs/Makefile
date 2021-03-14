all: ca-cert.pem key.pem full-cert.pem trust-root.json zk-params.json

ca-cert.pem: ca.cnf
	openssl req -new -x509 -config ca.cnf -days 36500 \
		-keyout ca-key.pem -out ca-cert.pem

key.pem:
	openssl genrsa -out key.pem 4096

csr.pem: main.cnf key.pem
	openssl req -new -config main.cnf -key key.pem -out csr.pem

cert.pem: csr.pem ca-cert.pem ca-key.pem
	openssl x509 -req \
		-extfile main.cnf \
		-in csr.pem \
		-days 36500 \
		-passin "pass:password" \
		-CA ca-cert.pem \
		-CAkey ca-key.pem \
		-CAcreateserial \
		-out cert.pem

full-cert.pem: cert.pem ca-cert.pem
	cat cert.pem ca-cert.pem > $@

trust-root.json:
	node generate-trust-root.js $@

zk-params.json:
	node generate-zk-params.js $@

.PHONY: all
