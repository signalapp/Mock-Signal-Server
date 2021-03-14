// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import assert from 'assert';
import { v4 as uuidv4 } from 'uuid';
import { PrivateKey } from '@signalapp/signal-client';
import { ServerSecretParams } from '@signalapp/signal-client/zkgroup';

import {
  generateSenderCertificate,
  generateServerCertificate,
} from '../src/crypto';
import { Device } from '../src/data/device';
import { PrimaryDevice } from '../src/api/primary-device';

const trustRoot = PrivateKey.generate();
const serverCert = generateServerCertificate(trustRoot);
const serverSecretParams = ServerSecretParams.generate();

async function createPrimaryDevice(name: string): Promise<PrimaryDevice> {
  const uuid = uuidv4();
  const pni = uuidv4();

  const device = new Device({
    uuid,
    pni,
    number: '+1',
    deviceId: 1,
    registrationId: 1,
  });

  const primary = new PrimaryDevice(device, {
    trustRoot: trustRoot.getPublicKey(),
    serverPublicParams: serverSecretParams.getPublicParams(),
    profileName: name,
    contacts: {},
    groups: {},

    async getSenderCertificate() {
      return generateSenderCertificate(serverCert, {
        number: device.number,
        uuid: device.uuid,
        deviceId: device.deviceId,
        identityKey: await device.getIdentityKey(),
      });
    },

    async send() {
      throw new Error('Should not be called');
    },
    async getDeviceByUUID() {
      throw new Error('Not implemented');
    },
    async issueProfileKeyCredential() {
      throw new Error('Not implemented');
    },
    async createGroup() {
      throw new Error('Not implemented');
    },
    async getStorageManifest() {
      throw new Error('Not implemented');
    },
    async getStorageItem() {
      throw new Error('Not implemented');
    },
    async waitForStorageManifest() {
      throw new Error('Not implemented');
    },
    async applyStorageWrite() {
      throw new Error('Not implemented');
    },
  });

  await primary.init();

  return primary;
}

// The idea of the test here is to verify that PrimaryDevice is capable of:
// - Generating prekeys
// - Adding prekeys from other accounts
// - Encrypting/decrypting messages
describe('PrimaryDevice', () => {
  it('should send and receive messages', async () => {
    const alice = await createPrimaryDevice('Alice');
    const bob = await createPrimaryDevice('Bob');

    const key = await bob.device.popSingleUseKey();
    await alice.addSingleUseKey(bob.device, key);

    const encrypted = await alice.encryptText(bob.device, 'Hello');
    await bob.receive(alice.device, encrypted);

    const message = await bob.waitForMessage();
    assert.strictEqual(message.body, 'Hello');
    assert.strictEqual(message.source, alice.device);
  });
});
