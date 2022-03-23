'use strict';

const fs = require('fs');
const { PrivateKey } = require('@signalapp/libsignal-client');

const rootKey = PrivateKey.generate();

fs.writeFileSync(process.argv[2], JSON.stringify({
  privateKey: rootKey.serialize().toString('base64'),
  publicKey: rootKey.getPublicKey().serialize().toString('base64'),
}, null, 2));
