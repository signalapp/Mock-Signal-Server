// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import { hkdf } from '@signalapp/libsignal-client';

const KEY_LABEL = Buffer.from(
  'Signal_Group_Call_20211105_SignallingDH_SRTPKey_KDF',
);

const KEY_LENGTH = 16;
const SALT_LENGTH = 12;

// In the order [client_key, client_salt, server_key, server_salt]
const KEY_MATERIAL_LENGTH = KEY_LENGTH + SALT_LENGTH + KEY_LENGTH + SALT_LENGTH;

export type StrpKeyMaterial = Uint8Array<ArrayBuffer> & {
  StrpKeyMaterial: Uint8Array<ArrayBuffer>;
};

export function getStrpKeyMaterial(params: {
  sharedSecret: Uint8Array<ArrayBuffer>;
  clientHkdfExtraInfo: Uint8Array<ArrayBuffer> | null;
}): StrpKeyMaterial {
  const clientHkdfExtraInfo = params.clientHkdfExtraInfo ?? Buffer.alloc(0);

  const keyMaterial = hkdf(
    KEY_MATERIAL_LENGTH,
    params.sharedSecret,
    Buffer.concat([KEY_LABEL, clientHkdfExtraInfo]),
    null,
  );

  return keyMaterial as StrpKeyMaterial;
}

type Key = Uint8Array<ArrayBuffer> & { Key: never };
type Salt = Uint8Array<ArrayBuffer> & { Salt: never };

type KeyPair = Readonly<{
  key: Key;
  salt: Salt;
}>;

type KeyPairs = Readonly<{
  rtp: KeyPair;
  rtcp: KeyPair;
}>;

type ClientAndServer = Readonly<{
  client: KeyPairs; // decrypt
  server: KeyPairs; // encrypt
}>;

export function deriveStrpClientAndServer(
  keyMaterial: StrpKeyMaterial,
): ClientAndServer {
  const mid = KEY_LENGTH + SALT_LENGTH;
  return {
    client: deriveKeyPairs({
      key: keyMaterial.subarray(0, KEY_LENGTH) as Key,
      salt: keyMaterial.subarray(KEY_LENGTH, mid) as Salt,
    }),
    server: deriveKeyPairs({
      key: keyMaterial.subarray(mid, mid + KEY_LENGTH) as Key,
      salt: keyMaterial.subarray(mid + KEY_LENGTH) as Salt,
    }),
  };
}

function deriveKeyPairs(master: KeyPair): KeyPairs {
  return {
    rtp: {
      key: deriveKey(master, 0),
      salt: deriveSalt(master, 2),
    },
    rtcp: {
      key: deriveKey(master, 3),
      salt: deriveSalt(master, 5),
    },
  };
}

// eslint-disable-next-line @typescript-eslint/no-unused-vars
function deriveKey(keyPair: KeyPair, label: number): Key {
  throw new Error('unimplemented');
}

// eslint-disable-next-line @typescript-eslint/no-unused-vars
function deriveSalt(keyPair: KeyPair, label: number): Salt {
  throw new Error('unimplemented');
}
