// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import createDebug from 'debug';
import { ProtocolAddress, PublicKey } from '@signalapp/libsignal-client';
import { ProfileKeyCommitment } from '@signalapp/libsignal-client/zkgroup';

import { DeviceId, RegistrationId, UUID, UUIDKind } from '../types';

const debug = createDebug('mock:device');

export interface DeviceOptions {
  readonly uuid: UUID;
  readonly pni: UUID;
  readonly number: string;
  readonly deviceId: DeviceId;
  readonly registrationId: RegistrationId;
}

export interface SignedPreKey {
  readonly keyId: number;
  readonly publicKey: PublicKey;
  readonly signature: Buffer;
}

export interface PreKey {
  readonly keyId: number;
  readonly publicKey: PublicKey;
}

export interface DeviceKeys {
  readonly identityKey: PublicKey;
  readonly signedPreKey: SignedPreKey;
  readonly preKeys: ReadonlyArray<PreKey>;
}

export interface SingleUseKey {
  readonly identityKey: PublicKey;
  readonly signedPreKey: SignedPreKey;
  readonly preKey: PreKey | undefined;
}

interface InternalDeviceKeys {
  readonly identityKey: PublicKey;
  readonly signedPreKey: SignedPreKey;
  readonly preKeys: Array<PreKey>;
}

export class Device {
  public readonly uuid: UUID;
  public readonly pni: UUID;
  public readonly number: string;
  public readonly deviceId: DeviceId;
  public readonly registrationId: RegistrationId;
  public readonly address: ProtocolAddress;

  public accessKey?: Buffer;
  public profileKeyCommitment?: ProfileKeyCommitment;
  public profileName?: Buffer;

  private keys: InternalDeviceKeys | undefined;

  constructor(options: DeviceOptions) {
    this.uuid = options.uuid;
    this.pni = options.pni;
    this.number = options.number;
    this.deviceId = options.deviceId;
    this.registrationId = options.registrationId;

    this.address = ProtocolAddress.new(this.uuid, this.deviceId);
  }

  public get debugId(): string {
    return `${this.uuid}.${this.deviceId}`;
  }

  public async setKeys(keys: DeviceKeys): Promise<void> {
    debug('setting keys for %s', this.debugId);

    // TODO(indutny): concat old preKeys with new ones?
    this.keys = {
      identityKey: keys.identityKey,
      signedPreKey: keys.signedPreKey,
      preKeys: keys.preKeys.slice(),
    };
  }

  public async getIdentityKey(): Promise<PublicKey> {
    if (!this.keys) {
      throw new Error('No keys available for device');
    }
    return this.keys.identityKey;
  }

  public async popSingleUseKey(): Promise<SingleUseKey> {
    if (!this.keys) {
      throw new Error('No keys available for device');
    }

    debug('popping single use key for %s', this.debugId);

    const preKey = this.keys.preKeys.shift();

    return {
      identityKey: this.keys.identityKey,
      signedPreKey: this.keys.signedPreKey,
      preKey,
    };
  }

  public async getSingleUseKeyCount(): Promise<number> {
    if (!this.keys) {
      throw new Error('No keys available for device');
    }
    return this.keys.preKeys.length;
  }

  public getUUIDByKind(uuidKind: UUIDKind): UUID {
    switch (uuidKind) {
    case UUIDKind.ACI:
      return this.uuid;
    case UUIDKind.PNI:
      return this.pni;
    }
  }
}
