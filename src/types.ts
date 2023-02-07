// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import { PublicKey } from '@signalapp/libsignal-client';

export type UUID = string;
export type ProvisioningCode = string;
export type RegistrationId = number;
export type DeviceId = number;
export type AttachmentId = string;

export enum UUIDKind {
  ACI = 'ACI',
  PNI = 'PNI'
}

export type SignedPreKey = Readonly<{
  keyId: number;
  publicKey: PublicKey;
  signature: Buffer;
}>;

export type PreKey = Readonly<{
  keyId: number;
  publicKey: PublicKey;
}>;
