// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import {
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPair,
  KeyObject,
} from 'node:crypto';
import { promisify } from 'node:util';

/**
 * These classses are a reimplementation of libsignal's PublicKey/PrivateKey
 * because they expect a tag at the start of their bytes.
 */

const generateKeyPairAsync = promisify(generateKeyPair);

export class CallingPrivateKey {
  #privateKey: KeyObject;

  constructor(privateKey: KeyObject) {
    this.#privateKey = privateKey;
  }

  static getPrivateKeyObject(privateKey: CallingPrivateKey): KeyObject {
    return privateKey.#privateKey;
  }

  static fromBytes(bytes: Uint8Array<ArrayBuffer>): CallingPrivateKey {
    return new CallingPrivateKey(
      createPrivateKey({
        key: bytes,
        format: 'raw-private',
        asymmetricKeyType: 'x25519',
      }),
    );
  }

  public toBytes(): Uint8Array<ArrayBuffer> {
    return this.#privateKey.export({
      format: 'raw-private',
    });
  }

  public agree(publicKey: CallingPublicKey): Uint8Array<ArrayBuffer> {
    return diffieHellman({
      privateKey: this.#privateKey,
      publicKey: CallingPublicKey.getPublicKeyObject(publicKey),
    });
  }
}

export class CallingPublicKey {
  #publicKey: KeyObject;

  constructor(publicKey: KeyObject) {
    this.#publicKey = publicKey;
  }

  static getPublicKeyObject(publicKey: CallingPublicKey): KeyObject {
    return publicKey.#publicKey;
  }

  static fromBytes(bytes: Uint8Array<ArrayBuffer>): CallingPublicKey {
    return new CallingPublicKey(
      createPublicKey({
        key: bytes,
        format: 'raw-public',
        asymmetricKeyType: 'x25519',
      }),
    );
  }

  getKeyObject(): KeyObject {
    return this.#publicKey;
  }

  toBytes(): Uint8Array<ArrayBuffer> {
    return this.#publicKey.export({
      format: 'raw-public',
    });
  }
}

export class CallingKeyPair {
  #privateKey: CallingPrivateKey;
  #publicKey: CallingPublicKey;

  private constructor(params: {
    privateKey: CallingPrivateKey;
    publicKey: CallingPublicKey;
  }) {
    this.#privateKey = params.privateKey;
    this.#publicKey = params.publicKey;
  }

  get privateKey(): CallingPrivateKey {
    return this.#privateKey;
  }

  get publicKey(): CallingPublicKey {
    return this.#publicKey;
  }

  static async generate(): Promise<CallingKeyPair> {
    const keys = await generateKeyPairAsync('x25519');
    return new CallingKeyPair({
      privateKey: new CallingPrivateKey(keys.privateKey),
      publicKey: new CallingPublicKey(keys.publicKey),
    });
  }
}
