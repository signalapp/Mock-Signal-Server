// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import createDebug from 'debug';
import { ProtocolAddress, PublicKey } from '@signalapp/libsignal-client';
import { ProfileKeyCommitment } from '@signalapp/libsignal-client/zkgroup';

import { DeviceId, RegistrationId, UUID, UUIDKind } from '../types';

const debug = createDebug('mock:device');

export type DeviceOptions = Readonly<{
  uuid: UUID;
  pni: UUID;
  number: string;
  deviceId: DeviceId;
  registrationId: RegistrationId;
  pniRegistrationId: RegistrationId;
}>;

export type ChangeNumberOptions = Readonly<{
  number: string;
  pni: UUID;
  pniRegistrationId: RegistrationId;
}>;

export type SignedPreKey = Readonly<{
  keyId: number;
  publicKey: PublicKey;
  signature: Buffer;
}>;

export type PreKey = Readonly<{
  keyId: number;
  publicKey: PublicKey;
}>;

export type DeviceKeys = Readonly<{
  identityKey: PublicKey;
  signedPreKey: SignedPreKey;
  preKeys: ReadonlyArray<PreKey>;
}>;

export type SingleUseKey = Readonly<{
  identityKey: PublicKey;
  signedPreKey: SignedPreKey;
  preKey: PreKey | undefined;
}>;

type InternalDeviceKeys = Readonly<{
  identityKey: PublicKey;
  signedPreKey: SignedPreKey;
  preKeys: Array<PreKey>;
}>;

export class Device {
  public readonly uuid: UUID;
  public readonly deviceId: DeviceId;
  public readonly address: ProtocolAddress;

  public accessKey?: Buffer;
  public profileKeyCommitment?: ProfileKeyCommitment;
  public profileName?: Buffer;

  private keys = new Map<UUIDKind, InternalDeviceKeys>();

  private privPni: UUID;
  private privNumber: string;
  private privPniAddress: ProtocolAddress;
  private readonly registrationId: RegistrationId;
  private pniRegistrationId: RegistrationId;

  constructor(options: DeviceOptions) {
    this.uuid = options.uuid;
    this.deviceId = options.deviceId;
    this.registrationId = options.registrationId;

    this.privPni = options.pni;
    this.privNumber = options.number;
    this.pniRegistrationId = options.pniRegistrationId;

    this.address = ProtocolAddress.new(this.uuid, this.deviceId);
    this.privPniAddress = ProtocolAddress.new(this.pni, this.deviceId);
  }

  public get debugId(): string {
    return `${this.uuid}.${this.deviceId}`;
  }

  public getRegistrationId(uuidKind: UUIDKind): number {
    switch (uuidKind) {
    case UUIDKind.ACI:
      return this.registrationId;
    case UUIDKind.PNI:
      return this.pniRegistrationId;
    }
  }

  public get pni(): UUID {
    return this.privPni;
  }

  public get number(): string {
    return this.privNumber;
  }

  public get pniAddress(): ProtocolAddress {
    return this.privPniAddress;
  }

  public async changeNumber({
    number,
    pni,
    pniRegistrationId,
  }: ChangeNumberOptions): Promise<void> {
    this.privNumber = number;
    this.privPni = pni;
    this.pniRegistrationId = pniRegistrationId;
    this.privPniAddress = ProtocolAddress.new(this.pni, this.deviceId);
  }

  public async setKeys(uuidKind: UUIDKind, keys: DeviceKeys): Promise<void> {
    debug('setting %s keys for %s', uuidKind, this.debugId);

    this.keys.set(uuidKind, {
      identityKey: keys.identityKey,
      signedPreKey: keys.signedPreKey,
      preKeys: keys.preKeys.slice(),
    });
  }

  public async getIdentityKey(uuidKind = UUIDKind.ACI): Promise<PublicKey> {
    const keys = this.keys.get(uuidKind);
    if (!keys) {
      throw new Error('No keys available for device');
    }
    return keys.identityKey;
  }

  public async popSingleUseKey(uuidKind = UUIDKind.ACI): Promise<SingleUseKey> {
    const keys = this.keys.get(uuidKind);
    if (!keys) {
      throw new Error('No keys available for device');
    }

    debug('popping single use key for %s', this.debugId);

    const preKey = keys.preKeys.shift();

    return {
      identityKey: keys.identityKey,
      signedPreKey: keys.signedPreKey,
      preKey,
    };
  }

  public async getSingleUseKeyCount(uuidKind = UUIDKind.ACI): Promise<number> {
    const keys = this.keys.get(uuidKind);
    if (!keys) {
      throw new Error('No keys available for device');
    }
    return keys.preKeys.length;
  }

  public getUUIDByKind(uuidKind: UUIDKind): UUID {
    switch (uuidKind) {
    case UUIDKind.ACI:
      return this.uuid;
    case UUIDKind.PNI:
      return this.pni;
    }
  }

  public getUUIDKind(uuid: UUID): UUIDKind {
    if (uuid === this.uuid) {
      return UUIDKind.ACI;
    }
    if (uuid === this.pni) {
      return UUIDKind.PNI;
    }
    throw new Error(`Unknown uuid: ${uuid}`);
  }

  public getAddressByKind(uuidKind: UUIDKind): ProtocolAddress {
    switch (uuidKind) {
    case UUIDKind.ACI:
      return this.address;
    case UUIDKind.PNI:
      return this.pniAddress;
    }
  }
}
