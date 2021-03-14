## Certificates

This folder contains various certificates required to run the mock server.

### Rebuilding

There shouldn't be a reason for rebuilding certificates bcause they have very
long expiration value, however if needed it could be done by:

- Installing node.js (16 or later), make, and openssl
- Run `make -B` in this folder
