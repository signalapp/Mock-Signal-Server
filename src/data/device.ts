// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import { timingSafeEqual } from 'node:crypto';
import createDebug from 'debug';
import {
  Aci,
  Pni,
  ProtocolAddress,
  PublicKey,
} from '@signalapp/libsignal-client';
import {
  BackupLevel,
  ProfileKeyCommitment,
} from '@signalapp/libsignal-client/zkgroup';

import {
  AciString,
  DeviceId,
  KyberPreKey,
  PniString,
  PreKey,
  RegistrationId,
  ServiceIdKind,
  ServiceIdString,
  SignedPreKey,
} from '../types';

const debug = createDebug('mock:device');

export type DeviceOptions = Readonly<{
  aci: AciString;
  pni: PniString;
  number: string;
  deviceId: DeviceId;
  registrationId: RegistrationId;
  pniRegistrationId: RegistrationId;
  isProvisioned: boolean;
}>;

export type ChangeNumberOptions = Readonly<{
  number: string;
  pni: PniString;
  pniRegistrationId: RegistrationId;
}>;

export type DeviceKeys = Readonly<{
  identityKey: PublicKey;
  preKeys?: ReadonlyArray<PreKey>;
  kyberPreKeys?: ReadonlyArray<KyberPreKey>;
  lastResortKey?: KyberPreKey;
  signedPreKey?: SignedPreKey;

  preKeyIterator?: AsyncIterator<PreKey>;
  kyberPreKeyIterator?: AsyncIterator<KyberPreKey>;
}>;

export type SingleUseKey = Readonly<{
  identityKey: PublicKey;

  signedPreKey: SignedPreKey;
  preKey: PreKey | undefined;
  pqPreKey: KyberPreKey;
}>;

type InternalDeviceKeys = Readonly<{
  identityKey: PublicKey;
  signedPreKey: SignedPreKey;
  lastResortKey: KyberPreKey;
  preKeys: Array<PreKey>;
  kyberPreKeys: Array<KyberPreKey>;
  preKeyIterator?: AsyncIterator<PreKey>;
  kyberPreKeyIterator?: AsyncIterator<KyberPreKey>;
}>;

// Technically, it is infinite.
const PRE_KEY_ITERATOR_COUNT = 100;

export class Device {
  public readonly aci: AciString;
  public readonly deviceId: DeviceId;
  public readonly address: ProtocolAddress;

  // If `true` - the device was provisioned and should receive messages over
  // the websocket.
  public readonly isProvisioned: boolean;

  public capabilities: {
    deleteSync: boolean;
    versionedExpirationTimer: boolean;
    ssre2: boolean;
  };

  public backupLevel = BackupLevel.Paid;
  public accessKey?: Buffer;
  public profileKeyCommitment?: ProfileKeyCommitment;
  public profileName?: Buffer;

  private keys = new Map<ServiceIdKind, InternalDeviceKeys>();

  private privPni: PniString;
  private privNumber: string;
  private privPniAddress: ProtocolAddress;
  private readonly registrationId: RegistrationId;
  private pniRegistrationId: RegistrationId;

  constructor(options: DeviceOptions) {
    this.aci = options.aci;
    this.deviceId = options.deviceId;
    this.registrationId = options.registrationId;

    this.privPni = options.pni;
    this.privNumber = options.number;
    this.pniRegistrationId = options.pniRegistrationId;

    this.isProvisioned = options.isProvisioned;

    this.address = ProtocolAddress.new(this.aci, this.deviceId);
    this.privPniAddress = ProtocolAddress.new(this.pni, this.deviceId);
    this.capabilities = {
      deleteSync: true,
      versionedExpirationTimer: true,
      ssre2: true,
    };
  }

  public get debugId(): string {
    return `${this.aci}.${this.deviceId}`;
  }

  public getRegistrationId(serviceIdKind: ServiceIdKind): number {
    switch (serviceIdKind) {
      case ServiceIdKind.ACI:
        return this.registrationId;
      case ServiceIdKind.PNI:
        return this.pniRegistrationId;
    }
  }

  public get aciBinary(): Uint8Array {
    return Aci.parseFromServiceIdString(this.aci).getServiceIdBinary();
  }

  public get pni(): PniString {
    return this.privPni;
  }

  public get pniBinary(): Uint8Array {
    return Pni.parseFromServiceIdString(this.pni).getServiceIdBinary();
  }

  public get aciRawUuid(): Uint8Array {
    return Aci.parseFromServiceIdString(this.aci).getRawUuidBytes();
  }

  public get pniRawUuid(): Uint8Array {
    return Pni.parseFromServiceIdString(this.pni).getRawUuidBytes();
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

  public async setKeys(
    serviceIdKind: ServiceIdKind,
    keys: DeviceKeys,
  ): Promise<void> {
    debug('setting %s keys for %s', serviceIdKind, this.debugId);
    const existingKeys = this.keys.get(serviceIdKind);
    const {
      signedPreKey = existingKeys?.signedPreKey,
      lastResortKey = existingKeys?.lastResortKey,
    } = keys;

    if (!signedPreKey) {
      throw new Error('setKeys: Missing signedPreKey');
    }
    if (!lastResortKey) {
      throw new Error('setKeys: Missing lastResortKey');
    }

    this.keys.set(serviceIdKind, {
      identityKey: keys.identityKey,

      signedPreKey,
      preKeys: keys.preKeys?.slice() ?? [],
      kyberPreKeys: keys.kyberPreKeys?.slice() ?? [],
      lastResortKey,

      preKeyIterator: keys.preKeyIterator,
      kyberPreKeyIterator: keys.kyberPreKeyIterator,
    });
  }

  public async getIdentityKey(
    serviceIdKind = ServiceIdKind.ACI,
  ): Promise<PublicKey> {
    const keys = this.keys.get(serviceIdKind);
    if (!keys) {
      throw new Error('No keys available for device');
    }
    return keys.identityKey;
  }

  public async popSingleUseKey(
    serviceIdKind = ServiceIdKind.ACI,
  ): Promise<SingleUseKey> {
    const keys = this.keys.get(serviceIdKind);
    if (!keys) {
      throw new Error('No keys available for device');
    }

    debug('popping single use key for %s', this.debugId);

    let preKey: PreKey | undefined;
    if (keys.preKeyIterator) {
      const { value } = await keys.preKeyIterator.next();
      preKey = value;
    }
    if (!preKey) {
      preKey = keys.preKeys.shift();
    }

    let pqPreKey: KyberPreKey | undefined;
    if (keys.kyberPreKeyIterator) {
      const { value } = await keys.kyberPreKeyIterator.next();
      pqPreKey = value;
    }
    if (!pqPreKey) {
      pqPreKey = keys.kyberPreKeys.shift();
    }
    if (!pqPreKey) {
      pqPreKey = keys.lastResortKey;
    }
    if (!pqPreKey) {
      throw new Error(
        'popSingleUseKey: Missing pqPreKey; checked iterator/array/lastResort',
      );
    }

    return {
      identityKey: keys.identityKey,
      signedPreKey: keys.signedPreKey,
      preKey,
      pqPreKey,
    };
  }

  public async getPreKeyCount(
    serviceIdKind = ServiceIdKind.ACI,
  ): Promise<number> {
    const keys = this.keys.get(serviceIdKind);
    if (!keys) {
      throw new Error('No keys available for device');
    }
    if (keys.preKeyIterator) {
      return PRE_KEY_ITERATOR_COUNT;
    }
    return keys.preKeys.length;
  }

  public async getKyberPreKeyCount(
    serviceIdKind = ServiceIdKind.ACI,
  ): Promise<number> {
    const keys = this.keys.get(serviceIdKind);
    if (!keys) {
      throw new Error('No keys available for device');
    }
    if (keys.kyberPreKeyIterator) {
      return PRE_KEY_ITERATOR_COUNT;
    }
    return keys.kyberPreKeys.length;
  }

  public getServiceIdByKind(serviceIdKind: ServiceIdKind): ServiceIdString {
    switch (serviceIdKind) {
      case ServiceIdKind.ACI:
        return this.aci;
      case ServiceIdKind.PNI:
        return this.pni;
    }
  }

  public getServiceIdBinaryByKind(serviceIdKind: ServiceIdKind): Uint8Array {
    switch (serviceIdKind) {
      case ServiceIdKind.ACI:
        return this.aciBinary;
      case ServiceIdKind.PNI:
        return this.pniBinary;
    }
  }

  public getServiceIdKind(serviceId: ServiceIdString): ServiceIdKind {
    if (serviceId === this.aci) {
      return ServiceIdKind.ACI;
    }
    if (serviceId === this.pni) {
      return ServiceIdKind.PNI;
    }
    throw new Error(`Unknown serviceId: ${serviceId}`);
  }

  public getServiceIdBinaryKind(serviceIdBinary: Uint8Array): ServiceIdKind {
    if (timingSafeEqual(serviceIdBinary, this.aciBinary)) {
      return ServiceIdKind.ACI;
    }
    if (timingSafeEqual(serviceIdBinary, this.pniBinary)) {
      return ServiceIdKind.PNI;
    }
    throw new Error('Unknown serviceId');
  }

  public getAddressByKind(serviceIdKind: ServiceIdKind): ProtocolAddress {
    switch (serviceIdKind) {
      case ServiceIdKind.ACI:
        return this.address;
      case ServiceIdKind.PNI:
        return this.pniAddress;
    }
  }
}
