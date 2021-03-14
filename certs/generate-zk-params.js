'use strict';

const fs = require('fs');
const { ServerSecretParams } = require('@signalapp/signal-client/zkgroup');

const secretParams = ServerSecretParams.generate();
const publicParams = secretParams.getPublicParams();

fs.writeFileSync(process.argv[2], JSON.stringify({
  secretParams: secretParams.serialize().toString('base64'),
  publicParams: publicParams.serialize().toString('base64'),
}, null, 2));
