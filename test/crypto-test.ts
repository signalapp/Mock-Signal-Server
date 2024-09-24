// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import assert from 'assert';
import { PrivateKey } from '@signalapp/libsignal-client';

import { deriveAccessKey, generateServerCertificate } from '../src/crypto';

describe('crypto', () => {
  // Verify that the generated certificate is valid within our trust root
  it('should create ServerCertificate', () => {
    const root = PrivateKey.generate();

    const { certificate } = generateServerCertificate(root);

    if (!certificate.signature || !certificate.certificate) {
      throw new Error('Invalid cert');
    }

    assert.ok(
      root
        .getPublicKey()
        .verify(
          Buffer.from(certificate.certificate),
          Buffer.from(certificate.signature),
        ),
    );
  });

  // Make sure that access key has correct value when derived from a constant
  // input.
  it('should derive access key', () => {
    const profileKey = Buffer.alloc(32).fill(42);
    const accessKey = deriveAccessKey(profileKey);

    assert.strictEqual(
      accessKey.toString('base64'),
      '2KEiuqkfT794/nwyqqVUYQ==',
    );
  });
});
