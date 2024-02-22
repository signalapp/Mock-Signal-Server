'use strict';

const fs = require('fs');
const { GenericServerSecretParams, ServerSecretParams } = require('@signalapp/libsignal-client/zkgroup');

const secretParams = ServerSecretParams.generate();
const publicParams = secretParams.getPublicParams();
const genericSecretParams = GenericServerSecretParams.generate();
const genericPublicParams = genericSecretParams.getPublicParams();

fs.writeFileSync(process.argv[2], JSON.stringify({
  secretParams: secretParams.serialize().toString('base64'),
  publicParams: publicParams.serialize().toString('base64'),
  genericSecretParams: genericSecretParams.serialize().toString('base64'),
  genericPublicParams: genericPublicParams.serialize().toString('base64'),
}, null, 2));
