// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import { DeviceId, RegistrationId } from '../types';

export type JSONDeviceKeys = Readonly<{
  identityKey: string;
  signedPreKey: Readonly<{
    keyId: number;
    publicKey: string;
    signature: string;
  }>;
  preKeys: ReadonlyArray<{
    keyId: number;
    publicKey: string;
  }>;
}>;

export type JSONMessage = Readonly<{
  // NOTE: Envelope.Type
  type: number;
  destinationDeviceId: DeviceId,
  destinationRegistrationId: RegistrationId,
  content: string;
}>;

export type JSONMessageList = Readonly<{
  messages: ReadonlyArray<JSONMessage>;
  timestamp: number;
}>;
