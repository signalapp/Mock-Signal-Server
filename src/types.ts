// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import { KEMPublicKey, PublicKey } from '@signalapp/libsignal-client';

export type AciString = string & { __aci: never };
export type PniString = string & { __pni: never };
export type UntaggedPniString = string & { __untagged_pni: never };
export type ServiceIdString = AciString | PniString;

export type ProvisionIdString = string & { __provision_id: never };

export type ProvisioningCode = string & { __provisioning_code: never };
export type RegistrationId = number & { __reg_id: never };
export type DeviceId = number & { __device_id: never };
export type AttachmentId = string & { __attachment_id: never };

export enum ServiceIdKind {
  ACI = 'ACI',
  PNI = 'PNI'
}

export type SignedPreKey = Readonly<{
  keyId: number;
  publicKey: PublicKey;
  signature: Buffer;
}>;

export type KyberPreKey = Readonly<{
  keyId: number;
  publicKey: KEMPublicKey;
  signature: Buffer;
}>;

export type PreKey = Readonly<{
  keyId: number;
  publicKey: PublicKey;
}>;

export function untagPni(pni: PniString): UntaggedPniString {
  return pni.replace(/^PNI:/, '') as UntaggedPniString;
}

export function tagPni(pni: UntaggedPniString): PniString {
  return `PNI:${pni}` as PniString;
}
