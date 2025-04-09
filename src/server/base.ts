// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import {
  Aci,
  Pni,
  PublicKey,
  SenderCertificate,
  usernames,
} from '@signalapp/libsignal-client';
import {
  AuthCredentialPresentation,
  BackupAuthCredentialPresentation,
  BackupAuthCredentialRequest,
  BackupCredentialType,
  BackupLevel,
  CallLinkAuthCredentialResponse,
  CreateCallLinkCredentialRequest,
  CreateCallLinkCredentialResponse,
  GenericServerSecretParams,
  GroupPublicParams,
  ProfileKeyCredentialRequest,
  ServerSecretParams,
  ServerZkAuthOperations,
  ServerZkProfileOperations,
  UuidCiphertext,
} from '@signalapp/libsignal-client/zkgroup';
import assert from 'assert';
import https from 'https';
import crypto from 'crypto';
import createDebug from 'debug';
import Long from 'long';
import { v4 as uuidv4 } from 'uuid';
import { AddressInfo } from 'net';

import { signalservice as Proto } from '../../protos/compiled';
import {
  DAY_IN_SECONDS,
  MAX_GROUP_CREDENTIALS_DAYS,
  PRIMARY_DEVICE_ID,
  PROFILE_KEY_CREDENTIAL_EXPIRATION,
} from '../constants';
import { ServerCertificate, generateSenderCertificate } from '../crypto';
import { ChangeNumberOptions, Device, DeviceKeys } from '../data/device';
import {
  BackupHeaders,
  BackupMediaBatch,
  CreateCallLink,
  DeleteCallLink,
  Message,
  SetBackupId,
  SetBackupKey,
  UpdateCallLink,
  UsernameConfirmation,
  UsernameReservation,
} from '../data/schemas';
import {
  AciString,
  AttachmentId,
  DeviceId,
  PniString,
  ProvisionIdString,
  ProvisioningCode,
  RegistrationId,
  ServiceIdKind,
  ServiceIdString,
} from '../types';
import { getTodayInSeconds } from '../util';
import { ModifyGroupResult, ServerGroup } from './group';

export enum EnvelopeType {
  CipherText = 'CipherText',
  Plaintext = 'Plaintext',
  PreKey = 'PreKey',
  SealedSender = 'SealedSender',
  SenderKey = 'SenderKey',
}

export type ProvisioningResponse = Readonly<{
  envelope: Buffer;
}>;

export type CredentialsRange = Readonly<{
  from: number;
  to: number;
}>;

export type StorageCredentials = Readonly<{
  username: string;
  password: string;
}>;

export type Credentials = Array<{
  credential: string;
  redemptionTime: number;
}>;

export type BackupCredentials = Readonly<{
  messages: Credentials;
  media: Credentials;
}>;

export type ChallengeResponse = Readonly<{
  code: number;
  data: unknown;
}>;

export type PreparedMultiDeviceMessage = ReadonlyArray<[Device, Message]>;

export type ProvisionDeviceOptions = Readonly<{
  number: string;
  password: string;
  provisioningCode: ProvisioningCode;
  registrationId: RegistrationId;
  pniRegistrationId: RegistrationId;
}>;

export type RegisterDeviceOptions = Readonly<
  (
    | {
        primary?: undefined;
        provisionId?: ProvisionIdString;
        number: string;
        password: string;
      }
    | {
        primary: Device;
        provisionId?: undefined;
        number?: undefined;
        password?: string;
      }
  ) & {
    registrationId: RegistrationId;
    pniRegistrationId: RegistrationId;
  }
>;

export type PrepareMultiDeviceMessageResult = Readonly<
  | {
      status: 'stale';
      staleDevices: ReadonlyArray<number>;
    }
  | {
      status: 'incomplete';
      missingDevices: ReadonlyArray<number>;
      extraDevices: ReadonlyArray<number>;
    }
  | {
      status: 'unknown';
    }
  | {
      status: 'ok';
      targetServiceId: ServiceIdString;
      result: PreparedMultiDeviceMessage;
    }
>;

export type ConfirmUsernameResult = Readonly<{
  usernameLinkHandle?: string;
}>;

export type SetUsernameLinkResult = Readonly<{
  entropy: Uint8Array;
  serverId: string;
}>;

export type StorageWriteResult = Readonly<
  | {
      updated: false;
      manifest: Proto.IStorageManifest;
      error?: void;
    }
  | {
      updated: true;
      manifest?: void;
      error?: void;
    }
  | {
      updated?: void;
      error: string;
    }
>;

export type ModifyGroupOptions = Readonly<{
  group: ServerGroup;
  actions: Proto.GroupChange.IActions;
  aciCiphertext: Uint8Array;
  pniCiphertext: Uint8Array;
}>;

export type EncryptedStickerPack = Readonly<{
  id: Buffer;
  manifest: Buffer;
  stickers: ReadonlyArray<Buffer>;
}>;

export type IsSendRateLimitedOptions = Readonly<{
  source: ServiceIdString;
  target: ServiceIdString;
}>;

export { type ModifyGroupResult };

interface WebSocket {
  sendMessage(message: Buffer | 'empty'): Promise<void>;
}

interface SerializableCredential {
  serialize(): Buffer;
}

type AuthEntry = Readonly<{
  readonly password: string;
  readonly device: Device;
}>;

type StorageAuthEntry = Readonly<{
  username: string;
  password: string;
  device: Device;
}>;

type MessageQueueEntry = {
  readonly message: Buffer;
  resolve(): void;
  reject(error: Error): void;
};

export type CallLinkEntry = Readonly<{
  adminPasskey: Buffer;
  encryptedName: string;
  restrictions: 'none' | 'adminApproval';
  revoked: boolean;
  expiration: number;
}>;

export type BackupInfo = Readonly<{
  cdn: 3;
  backupDir: string;
  mediaDir: string;
  backupName: string;
  usedSpace?: number;
}>;

export type BackupMediaObject = Readonly<{
  cdn: 3;
  mediaId: string;
  objectLength: number;
}>;

export type BackupMediaList = Readonly<{
  storedMediaObjects: ReadonlyArray<BackupMediaObject>;
  backupDir: string;
  mediaDir: string;
  cursor: string | undefined;
}>;

export type BackupMediaCursor = {
  readonly backupId: string;
  remainingMedia: ReadonlyArray<BackupMediaObject>;
};

export type ListBackupMediaOptions = Readonly<{
  cursor: string | undefined;
  limit: number;
}>;

export type BackupMediaBatchResponse = Readonly<{
  status: number;
  failureReason?: string;
  cdn: 3;
  mediaId: string;
}>;

export type BackupMediaBatchResult = Readonly<{
  responses: ReadonlyArray<BackupMediaBatchResponse>;
}>;

export type TransferArchiveResponse = Readonly<
  | {
      error: 'RELINK_REQUESTED' | 'CONTINUE_WITHOUT_UPLOAD';
    }
  | {
      cdn: 3;
      key: string;
    }
>;

export type AttachmentUploadForm = Readonly<{
  cdn: 3;
  key: string;
  headers: Record<string, string>;
  signedUploadLocation: string;
}>;

export type RemoteConfigValueType = {
  enabled: boolean;
  value?: string;
};

const debug = createDebug('mock:server:base');

// NOTE: This class is currently extended only by src/api/server.ts
export abstract class Server {
  private readonly devices = new Map<string, Array<Device>>();
  private readonly devicesByServiceId = new Map<ServiceIdString, Device>();
  private readonly devicesByAuth = new Map<string, AuthEntry>();
  private readonly usedServiceIds = new Set<ServiceIdString>();
  private readonly usedProvisionIds = new Set<ProvisionIdString>();
  private readonly storageAuthByUsername = new Map<string, StorageAuthEntry>();
  private readonly storageAuthByDevice = new Map<Device, StorageAuthEntry>();
  private readonly storageManifestByAci = new Map<
    AciString,
    Proto.IStorageManifest
  >();
  private readonly storageItemsByAci = new Map<
    AciString,
    Map<string, Buffer>
  >();
  private readonly provisioningCodes = new Map<
    string,
    Map<ProvisioningCode, ProvisionIdString>
  >();
  private readonly attachments = new Map<AttachmentId, Buffer>();
  private readonly stickerPacks = new Map<string, EncryptedStickerPack>();
  private readonly webSockets = new Map<Device, Set<WebSocket>>();
  private readonly messageQueue = new WeakMap<
    Device,
    Array<MessageQueueEntry>
  >();
  private readonly groups = new Map<string, ServerGroup>();
  private readonly aciByUsername = new Map<string, AciString>();
  private readonly aciByReservedUsername = new Map<string, AciString>();
  private readonly usernameByAci = new Map<AciString, string>();
  private readonly reservedUsernameByAci = new Map<AciString, string>();
  private readonly usernameLinkIdByServiceId = new Map<
    ServiceIdString,
    string
  >();
  private readonly usernameLinkById = new Map<string, Buffer>();
  private readonly callLinksByRoomId = new Map<string, CallLinkEntry>();
  private readonly backupAuthReqByAci = new Map<
    AciString,
    {
      messages: BackupAuthCredentialRequest;
      media: BackupAuthCredentialRequest;
    }
  >();
  private readonly backupKeyById = new Map<string, PublicKey>();
  private readonly backupCDNPasswordById = new Map<string, string>();
  private readonly backupMediaById = new Map<
    string,
    Array<BackupMediaObject>
  >();
  private readonly backupMediaCursorById = new Map<string, BackupMediaCursor>();
  private readonly remoteConfig = new Map<string, RemoteConfigValueType>();
  protected privCertificate: ServerCertificate | undefined;
  protected privZKSecret: ServerSecretParams | undefined;
  protected privGenericServerSecret: GenericServerSecretParams | undefined;
  protected privBackupServerSecret: GenericServerSecretParams | undefined;
  protected https: https.Server | undefined;

  public address(): AddressInfo {
    if (!this.https) {
      throw new Error('Not listening');
    }

    const result = this.https.address();
    if (!result || typeof result !== 'object') {
      throw new Error('Invalid .address() result');
    }
    return result;
  }

  //
  // Service Ids
  //

  public async generateAci(): Promise<AciString> {
    let result: AciString;
    do {
      result = uuidv4() as AciString;
    } while (this.usedServiceIds.has(result));
    this.usedServiceIds.add(result);
    return result;
  }

  public async generatePni(): Promise<PniString> {
    let result: PniString;
    do {
      result = `PNI:${uuidv4()}` as PniString;
    } while (this.usedServiceIds.has(result));
    this.usedServiceIds.add(result);
    return result;
  }

  //
  // Provisioning
  //

  public async generateProvisionId(): Promise<ProvisionIdString> {
    let result: ProvisionIdString;
    do {
      result = uuidv4() as ProvisionIdString;
    } while (this.usedProvisionIds.has(result));
    this.usedProvisionIds.add(result);
    return result;
  }

  public async releaseProvisionId(id: ProvisionIdString): Promise<void> {
    this.usedProvisionIds.delete(id);
  }

  public abstract getProvisioningResponse(
    id: ProvisionIdString,
  ): Promise<ProvisioningResponse>;

  public async registerDevice({
    primary,
    provisionId,
    number: maybeNumber,
    registrationId,
    pniRegistrationId,
    password,
  }: RegisterDeviceOptions): Promise<Device> {
    if (provisionId && !this.usedProvisionIds.has(provisionId)) {
      throw new Error('Use generateProvisionId() to create new provision id');
    }

    let aci: AciString;
    let pni: PniString;
    let number: string;
    if (primary) {
      ({ aci, pni, number } = primary);
    } else {
      [aci, pni] = await Promise.all([this.generateAci(), this.generatePni()]);
      number = maybeNumber;
    }

    let list = this.devices.get(number);
    if (!list) {
      list = [];
      this.devices.set(number, list);
    }
    const deviceId = (list.length + 1) as DeviceId;
    const isPrimary = deviceId === PRIMARY_DEVICE_ID;

    const device = new Device({
      aci,
      pni,
      number,
      deviceId,
      registrationId,
      pniRegistrationId,
    });

    if (isPrimary) {
      assert(!this.devicesByServiceId.has(aci), 'Duplicate primary device');
      this.devicesByServiceId.set(aci, device);
      this.devicesByServiceId.set(pni, device);
    }

    if (password) {
      this.setDeviceAuthPassword(number, device, password);
    }

    list.push(device);

    debug('registered device number=%j aci=%s pni=%s', number, aci, pni);
    return device;
  }

  // Called from primary device
  public async getProvisioningCode(
    id: ProvisionIdString,
    number: string,
  ): Promise<ProvisioningCode> {
    let entry = this.provisioningCodes.get(number);
    if (!entry) {
      entry = new Map<ProvisioningCode, ProvisionIdString>();
      this.provisioningCodes.set(number, entry);
    }
    let code: ProvisioningCode;
    do {
      code = crypto.randomBytes(8).toString('hex') as ProvisioningCode;
    } while (entry.has(code));
    entry.set(code, id);
    return code;
  }

  // Called from secondary device
  public async provisionDevice({
    number,
    password,
    provisioningCode,
    registrationId,
    pniRegistrationId,
  }: ProvisionDeviceOptions): Promise<Device> {
    const entry = this.provisioningCodes.get(number);
    if (!entry) {
      throw new Error('Invalid number for provisioning');
    }

    const provisionIdString = entry.get(provisioningCode);
    if (!provisionIdString) {
      throw new Error('Invalid provisioning code');
    }
    entry.delete(provisioningCode);

    const [primary] = this.devices.get(number) || [];
    assert(primary !== undefined, 'Missing primary device when provisioning');

    const device = await this.registerDevice({
      primary,
      registrationId,
      pniRegistrationId,
      password,
    });

    debug(
      'provisioned device id=%j number=%j aci=%j',
      device.deviceId,
      number,
      device.aci,
    );
    return device;
  }

  private setDeviceAuthPassword(
    number: string,
    device: Device,
    password: string,
  ) {
    const username = `${number}.${device.deviceId}`;

    // This is awkward, but WebSockets use it.
    const secondUsername = `${device.aci}.${device.deviceId}`;

    // Add auth only after successfully registering the device
    assert(
      !this.devicesByAuth.has(username) &&
        !this.devicesByAuth.has(secondUsername),
      'Duplicate username in `provisionDevice`',
    );
    const authEntry = {
      password,
      device,
    };
    this.devicesByAuth.set(username, authEntry);
    this.devicesByAuth.set(secondUsername, authEntry);
  }

  public async updateDeviceKeys(
    device: Device,
    serviceIdKind: ServiceIdKind,
    keys: Omit<DeviceKeys, 'identityKey'>,
  ): Promise<void> {
    debug('setting device=%s keys', device.debugId);
    const primary = this.devicesByServiceId.get(device.aci);
    assert(primary, 'must have primary device');
    await device.setKeys(serviceIdKind, {
      ...keys,
      identityKey: await primary.getIdentityKey(serviceIdKind),
    });
  }

  public async changeDeviceNumber(
    device: Device,
    options: ChangeNumberOptions,
  ): Promise<void> {
    const oldNumber = device.number;
    const oldPni = device.pni;
    await device.changeNumber(options);

    const oldDevices = this.devices.get(oldNumber) ?? [];
    const oldDeviceIndex = oldDevices.indexOf(device);
    if (oldDeviceIndex !== -1) {
      oldDevices.splice(oldDeviceIndex, 1);
      if (oldDevices.length === 0) {
        this.devices.delete(oldNumber);
      }
    }

    let newDevices = this.devices.get(options.number);
    if (!newDevices) {
      newDevices = [];
      this.devices.set(options.number, newDevices);
    }
    newDevices.push(device);

    const oldPrimary = this.devicesByServiceId.get(oldPni);
    if (oldPrimary === device) {
      this.devicesByServiceId.delete(oldPni);
      this.devicesByServiceId.set(options.pni, device);
    }
  }

  //
  // Auth
  //

  public async auth(
    username: string,
    password: string,
  ): Promise<Device | undefined> {
    const entry = this.devicesByAuth.get(username);
    if (!entry) {
      debug('auth failed, username=%j is unknown', username);
      return;
    }
    if (entry.password !== password) {
      debug('auth failed, invalid login/password %j:%j', username, password);
      return;
    }
    return entry.device;
  }

  //
  // Remote config
  //
  public setRemoteConfig(key: string, value: RemoteConfigValueType) {
    this.remoteConfig.set(key, value);
  }

  public getRemoteConfig() {
    return this.remoteConfig;
  }

  //
  // CDN
  //

  protected async storeAttachment(attachment: Buffer): Promise<AttachmentId> {
    const id = crypto
      .createHash('sha256')
      .update(attachment)
      .digest('hex') as AttachmentId;
    this.attachments.set(id, attachment);
    return id;
  }

  public async fetchAttachment(id: AttachmentId): Promise<Buffer | undefined> {
    return this.attachments.get(id);
  }

  public async fetchStickerPack(packId: string): Promise<Buffer | undefined> {
    return this.stickerPacks.get(packId)?.manifest;
  }

  public async fetchSticker(
    packId: string,
    stickerId: number,
  ): Promise<Buffer | undefined> {
    return this.stickerPacks.get(packId)?.stickers[stickerId];
  }

  public async storeStickerPack(pack: EncryptedStickerPack): Promise<void> {
    this.stickerPacks.set(pack.id.toString('hex'), pack);
  }

  public async getAttachmentUploadForm(
    folder: string,
    key: string,
  ): Promise<AttachmentUploadForm> {
    const { port, family } = this.address();

    // These are the only two in the TLS certificate
    const host = family === 'IPv6' ? '[::1]' : '127.0.0.1';
    const signedUploadLocation = `https://${host}:${port}/cdn3/${folder}/${key}`;
    return {
      cdn: 3,
      key,
      headers: {
        // TODO(indutny): verify on request
        expectedHeaders: crypto.randomBytes(16).toString('hex'),
      },
      signedUploadLocation,
    };
  }

  //
  // Messages
  //

  public async prepareMultiDeviceMessage(
    source: Device | undefined,
    targetServiceId: ServiceIdString,
    messages: ReadonlyArray<Message>,
  ): Promise<PrepareMultiDeviceMessageResult> {
    if (this.isUnregistered(targetServiceId)) {
      return { status: 'unknown' };
    }

    const devices = await this.getAllDevicesByServiceId(targetServiceId);
    if (devices.length === 0) {
      return { status: 'unknown' };
    }

    const deviceById = new Map<DeviceId, Device>();
    for (const device of devices) {
      deviceById.set(device.deviceId, device);
    }

    const result = new Array<[Device, Message]>();

    const extraDevices = new Set<DeviceId>();
    const staleDevices = new Set<DeviceId>();
    for (const message of messages) {
      const { destinationDeviceId, destinationRegistrationId } = message;

      const target = deviceById.get(destinationDeviceId);
      if (!target) {
        extraDevices.add(destinationDeviceId);
        continue;
      }

      const serviceIdKind = target.getServiceIdKind(targetServiceId);

      deviceById.delete(destinationDeviceId);

      if (
        target.getRegistrationId(serviceIdKind) !== destinationRegistrationId
      ) {
        staleDevices.add(destinationDeviceId);
        continue;
      }

      result.push([target, message]);
    }

    if (source && source.aci === targetServiceId) {
      deviceById.delete(source.deviceId);
    }

    if (staleDevices.size !== 0) {
      return { status: 'stale', staleDevices: Array.from(staleDevices) };
    }

    if (extraDevices.size !== 0 || deviceById.size !== 0) {
      return {
        status: 'incomplete',
        missingDevices: Array.from(deviceById.keys()),
        extraDevices: Array.from(extraDevices),
      };
    }

    return { status: 'ok', targetServiceId, result };
  }

  public async handlePreparedMultiDeviceMessage(
    source: Device | undefined,
    targetServiceId: ServiceIdString,
    prepared: PreparedMultiDeviceMessage,
  ): Promise<void> {
    for (const [target, message] of prepared) {
      let envelopeType: EnvelopeType;
      if (message.type === Proto.Envelope.Type.CIPHERTEXT) {
        envelopeType = EnvelopeType.CipherText;
      } else if (message.type === Proto.Envelope.Type.PREKEY_BUNDLE) {
        envelopeType = EnvelopeType.PreKey;
      } else if (message.type === Proto.Envelope.Type.UNIDENTIFIED_SENDER) {
        envelopeType = EnvelopeType.SealedSender;
      } else if (message.type === Proto.Envelope.Type.PLAINTEXT_CONTENT) {
        envelopeType = EnvelopeType.Plaintext;
      } else {
        throw new Error(`Unsupported envelope type: ${message.type}`);
      }

      const serviceIdKind = target.getServiceIdKind(targetServiceId);

      await this.handleMessage(
        source,
        serviceIdKind,
        envelopeType,
        target,
        Buffer.from(message.content, 'base64'),
      );
    }
  }

  public abstract handleMessage(
    source: Device | undefined,
    serviceIdKind: ServiceIdKind,
    envelopeType: EnvelopeType,
    target: Device,
    encrypted: Buffer,
  ): Promise<void>;

  public async addWebSocket(device: Device, socket: WebSocket): Promise<void> {
    debug('adding websocket for device=%s', device.debugId);
    let sockets = this.webSockets.get(device);
    if (!sockets) {
      sockets = new Set();
      this.webSockets.set(device, sockets);
    }
    sockets.add(socket);

    await this.sendQueue(device, socket);
  }

  public removeWebSocket(device: Device, socket: WebSocket): void {
    debug('removing websocket for device=%s', device.debugId);
    const sockets = this.webSockets.get(device);
    if (!sockets) {
      return;
    }
    sockets.delete(socket);
    if (sockets.size === 0) {
      this.webSockets.delete(device);
    }
  }

  // TODO(indutny): timeout
  public async send(target: Device, message: Buffer): Promise<void> {
    const sockets = this.webSockets.get(target);
    if (sockets) {
      debug(
        'sending message to %d sockets of %s',
        sockets.size,
        target.debugId,
      );
      let success = false;
      await Promise.all<void>(
        Array.from(sockets).map(async (socket) => {
          try {
            await socket.sendMessage(message);
            success = true;
          } catch (error) {
            assert(error instanceof Error);
            debug(
              'failed to send message to socket of %s, error %s',
              target.debugId,
              error.message,
            );
          }
        }),
      );

      // At least one send should succeed, if not - queue
      if (success) {
        return;
      }

      debug("message couldn't be sent to %s", sockets.size, target.debugId);
    }

    debug('queueing message for device=%s', target.debugId);

    await new Promise<void>((resolve, reject) => {
      // NOTE: set and push have to happen in the same tick, otherwise a race
      // condition is possible in `removeWebSocket`.
      let queue = this.messageQueue.get(target);
      if (!queue) {
        queue = [];
        this.messageQueue.set(target, queue);
      }

      queue.push({
        message,
        resolve,
        reject,
      });
    });

    debug('queued message sent to device=%s', target.debugId);
  }

  //
  // Groups
  //

  public async createGroup(group: Proto.IGroup): Promise<ServerGroup> {
    const result = new ServerGroup({
      zkSecret: this.zkSecret,
      profileOps: new ServerZkProfileOperations(this.zkSecret),
      state: group,
    });

    const key = result.publicParams.serialize().toString('base64');

    if (this.groups.get(key)) {
      throw new Error('Duplicate group');
    }

    this.groups.set(key, result);

    return result;
  }

  public async modifyGroup({
    group,
    actions,
    aciCiphertext,
    pniCiphertext,
  }: ModifyGroupOptions): Promise<ModifyGroupResult> {
    return group.modify(
      new UuidCiphertext(Buffer.from(aciCiphertext)),
      new UuidCiphertext(Buffer.from(pniCiphertext)),
      actions,
    );
  }

  public async getGroup(
    publicParams: Buffer,
  ): Promise<ServerGroup | undefined> {
    return this.groups.get(publicParams.toString('base64'));
  }

  //
  // Storage
  //

  public async getStorageAuth(device: Device): Promise<StorageCredentials> {
    let auth = this.storageAuthByDevice.get(device);
    if (!auth) {
      do {
        auth = {
          username: crypto.randomBytes(8).toString('hex'),
          password: crypto.randomBytes(8).toString('hex'),
          device,
        };
      } while (this.storageAuthByUsername.has(auth.username));

      this.storageAuthByDevice.set(device, auth);
      this.storageAuthByUsername.set(auth.username, auth);

      debug('register new storage username=%j', auth.username);
    }

    return {
      username: auth.username,
      password: auth.password,
    };
  }

  public async storageAuth(
    username: string,
    password: string,
  ): Promise<Device | undefined> {
    const auth = this.storageAuthByUsername.get(username);
    if (!auth) {
      debug('auth failed, username=%j is unknown', username);
      return;
    }
    if (auth.password !== password) {
      debug('auth failed, invalid login/password %j:%j', username, password);
    }

    return auth.device;
  }

  public async getStorageManifest(
    device: Device,
  ): Promise<Proto.IStorageManifest | undefined> {
    return this.storageManifestByAci.get(device.aci);
  }

  public async applyStorageWrite(
    device: Device,
    { manifest, clearAll, insertItem, deleteKey }: Proto.IWriteOperation,
    shouldNotify = true,
  ): Promise<StorageWriteResult> {
    if (!manifest) {
      return { error: 'missing `writeOperation.manifest`' };
    }

    if (!manifest.version) {
      return {
        error:
          'not updating storage manifest, ' +
          'missing `writeOperation.manifest.version`',
      };
    }

    const existing = await this.getStorageManifest(device);
    if (existing) {
      // Atomicity
      assert(existing.version, 'consistency check');
      if (!manifest.version.eq(existing.version.add(1))) {
        debug(
          'not updating storage manifest, current version=%j new version=%j',
          existing.version.toNumber(),
          manifest.version.toNumber(),
        );
        return { updated: false, manifest: existing };
      }
    }

    if (clearAll) {
      debug('clearing storage items for=%j', device.debugId);
      await this.clearStorageItems(device);
    }

    const inserts = (insertItem || []).map(async (item) => {
      assert(item.key instanceof Uint8Array, 'insertItem.key must be a Buffer');
      assert(
        item.value instanceof Uint8Array,
        'insertItem.value must be a Buffer',
      );
      return this.setStorageItem(
        device,
        Buffer.from(item.key),
        Buffer.from(item.value),
      );
    });
    await Promise.all(inserts);

    const deletes = (deleteKey || []).map(async (key) => {
      return this.deleteStorageItem(device, Buffer.from(key));
    });
    await Promise.all(deletes);

    debug(
      'updating storage manifest to version=%j for=%j',
      manifest.version.toNumber(),
      device.debugId,
    );
    this.storageManifestByAci.set(device.aci, manifest);

    if (shouldNotify) {
      await this.onStorageManifestUpdate(device, manifest.version);
    }

    return { updated: true };
  }

  private async clearStorageItems(device: Device): Promise<void> {
    this.storageItemsByAci.get(device.aci)?.clear();
  }

  private async setStorageItem(
    device: Device,
    key: Buffer,
    value: Buffer,
  ): Promise<void> {
    let map = this.storageItemsByAci.get(device.aci);
    if (!map) {
      map = new Map();
      this.storageItemsByAci.set(device.aci, map);
    }

    map.set(key.toString('hex'), value);
  }

  public async getStorageItem(
    device: Device,
    key: Buffer,
  ): Promise<Buffer | undefined> {
    const map = this.storageItemsByAci.get(device.aci);
    if (!map) {
      return undefined;
    }

    return map.get(key.toString('hex'));
  }

  public async getAllStorageKeys(device: Device): Promise<Array<Buffer>> {
    const map = this.storageItemsByAci.get(device.aci);
    if (!map) {
      return [];
    }

    return Array.from(map.keys()).map((hex) => Buffer.from(hex, 'hex'));
  }

  public async getStorageItems(
    device: Device,
    keys: ReadonlyArray<Buffer>,
  ): Promise<Array<Proto.IStorageItem> | undefined> {
    const result = new Array<Proto.IStorageItem>();

    await Promise.all(
      keys.map(async (key) => {
        const value = await this.getStorageItem(device, key);
        if (value !== undefined) {
          result.push({ key, value });
        }
      }),
    );

    return result;
  }

  public async deleteStorageItem(device: Device, key: Buffer): Promise<void> {
    const map = this.storageItemsByAci.get(device.aci);
    if (!map) {
      return;
    }

    map.delete(key.toString('hex'));
  }

  protected abstract onStorageManifestUpdate(
    device: Device,
    version: Long,
  ): Promise<void>;

  //
  // Usernames
  //

  public async reserveUsername(
    aci: AciString,
    { usernameHashes }: UsernameReservation,
  ): Promise<Buffer | undefined> {
    // Clear previously reserved usernames
    const reserved = this.reservedUsernameByAci.get(aci);
    if (reserved !== undefined) {
      this.reservedUsernameByAci.delete(aci);
      this.aciByReservedUsername.delete(reserved);
    }

    for (const hash of usernameHashes) {
      const hashHex = hash.toString('hex');
      if (this.aciByReservedUsername.has(hashHex)) {
        continue;
      }
      if (this.aciByUsername.has(hashHex)) {
        continue;
      }

      this.reservedUsernameByAci.set(aci, hashHex);
      this.aciByReservedUsername.set(hashHex, aci);
      return hash;
    }

    return undefined;
  }

  public async confirmUsername(
    aci: AciString,
    { usernameHash, zkProof, encryptedUsername }: UsernameConfirmation,
  ): Promise<ConfirmUsernameResult | undefined> {
    // Clear previously reserved usernames
    const reserved = this.reservedUsernameByAci.get(aci);
    if (reserved !== usernameHash.toString('hex')) {
      return undefined;
    }

    try {
      usernames.verifyProof(zkProof, usernameHash);
    } catch (error) {
      debug('failed to verify username proof of %s: %O', aci, error);
      return undefined;
    }

    this.reservedUsernameByAci.delete(aci);
    this.aciByReservedUsername.delete(reserved);

    this.aciByUsername.set(reserved, aci);
    this.usernameByAci.set(aci, reserved);

    let usernameLinkHandle: string | undefined;
    if (encryptedUsername) {
      usernameLinkHandle = await this.replaceUsernameLink(
        aci,
        encryptedUsername,
      );
    }

    return { usernameLinkHandle };
  }

  public async deleteUsername(aci: AciString): Promise<void> {
    const hash = this.usernameByAci.get(aci);
    if (!hash) {
      return;
    }

    this.aciByUsername.delete(hash);
    this.usernameByAci.delete(aci);

    const previousId = this.usernameLinkIdByServiceId.get(aci);
    if (previousId !== undefined) {
      this.usernameLinkById.delete(previousId);
    }
    this.usernameLinkIdByServiceId.delete(aci);
  }

  public async lookupByUsernameHash(
    usernameHash: Buffer,
  ): Promise<AciString | undefined> {
    return this.aciByUsername.get(usernameHash.toString('hex'));
  }

  public async replaceUsernameLink(
    aci: AciString,
    encryptedValue: Buffer,
  ): Promise<string> {
    const lookupId = uuidv4();

    const previousId = this.usernameLinkIdByServiceId.get(aci);
    if (previousId !== undefined) {
      this.usernameLinkById.delete(previousId);
    }

    this.usernameLinkIdByServiceId.set(aci, lookupId);
    this.usernameLinkById.set(lookupId, encryptedValue);

    return lookupId;
  }

  public async lookupByUsernameLink(
    lookupId: string,
  ): Promise<Buffer | undefined> {
    return this.usernameLinkById.get(lookupId);
  }

  // For easier testing
  public async lookupByUsername(
    username: string,
  ): Promise<AciString | undefined> {
    return this.aciByUsername.get(usernames.hash(username).toString('hex'));
  }

  // For easier testing
  public async setUsername(aci: AciString, username: string): Promise<void> {
    const hash = usernames.hash(username).toString('hex');
    this.usernameByAci.set(aci, hash);
    this.aciByUsername.set(hash, aci);
  }

  // For easier testing
  public async setUsernameLink(
    aci: AciString,
    username: string,
  ): Promise<SetUsernameLinkResult> {
    const { entropy, encryptedUsername } =
      usernames.createUsernameLink(username);

    const serverId = await this.replaceUsernameLink(aci, encryptedUsername);

    return {
      entropy,
      serverId,
    };
  }

  //
  // Call Links
  //

  public async createCallLinkAuth(
    device: Device,
    request: CreateCallLinkCredentialRequest,
  ): Promise<CreateCallLinkCredentialResponse> {
    return request.issueCredential(
      Aci.parseFromServiceIdString(device.aci),
      getTodayInSeconds(),
      this.genericServerSecret,
    );
  }

  public hasCallLink(roomId: string) {
    return this.callLinksByRoomId.has(roomId);
  }

  public async createCallLink(
    roomId: string,
    { adminPasskey }: CreateCallLink,
  ): Promise<CallLinkEntry> {
    const callLink: CallLinkEntry = {
      adminPasskey,
      encryptedName: '',
      restrictions: 'none',
      revoked: false,
      expiration: new Date('2101-01-01').getTime(),
    };
    this.callLinksByRoomId.set(roomId, callLink);
    return callLink;
  }

  public async getCallLink(roomId: string): Promise<CallLinkEntry | undefined> {
    return this.callLinksByRoomId.get(roomId);
  }

  public async updateCallLink(
    roomId: string,
    { adminPasskey, name, restrictions, revoked }: UpdateCallLink,
  ): Promise<CallLinkEntry> {
    const callLink = this.callLinksByRoomId.get(roomId);
    if (!callLink) {
      throw new Error('Call link not found');
    }
    if (!callLink.adminPasskey.equals(adminPasskey)) {
      throw new Error('Invalid admin passkey');
    }
    const newCallLink: CallLinkEntry = {
      adminPasskey,
      encryptedName: name ?? callLink.encryptedName,
      restrictions: restrictions ?? callLink.restrictions,
      revoked: revoked ?? callLink.revoked,
      expiration: callLink.expiration,
    };
    this.callLinksByRoomId.set(roomId, newCallLink);
    return newCallLink;
  }

  public async deleteCallLink(
    roomId: string,
    { adminPasskey }: DeleteCallLink,
  ): Promise<void> {
    const callLink = this.callLinksByRoomId.get(roomId);
    if (!callLink) {
      throw new Error('Call link not found');
    }
    if (!callLink.adminPasskey.equals(adminPasskey)) {
      throw new Error('Invalid admin passkey');
    }
    this.callLinksByRoomId.delete(roomId);
  }

  //
  // Utils
  //

  public async getDevice(
    number: string,
    deviceId: DeviceId,
  ): Promise<Device | undefined> {
    const list = this.devices.get(number);
    if (!list) {
      return;
    }
    if (deviceId < 1 || deviceId > list.length) {
      return;
    }

    return list[deviceId - 1];
  }
  async removeDevice(number: string, deviceId: DeviceId): Promise<void> {
    if (deviceId === PRIMARY_DEVICE_ID) {
      throw new Error(
        'You cannot remove a primary device; unregister account instead',
      );
    }
    const list = this.devices.get(number);
    if (!list) {
      throw new Error(`No devices found for number ${number}`);
    }
    if (deviceId < 1 || deviceId > list.length) {
      throw new Error(
        `Device ${deviceId} is out of range for number ${number}`,
      );
    }

    const device = list[deviceId - 1];

    debug('removeDevice %j.%j (%j)', device.aci, deviceId, number);

    const copy = [...list];
    copy.splice(deviceId - 1, 1);
    this.devices.set(number, copy);

    const idByNumber = `${number}.${deviceId}`;
    this.devicesByAuth.delete(idByNumber);

    const idByAci = `${device.aci}.${deviceId}`;
    this.devicesByAuth.delete(idByAci);
  }

  public async getDeviceByServiceId(
    serviceId: ServiceIdString,
    deviceId?: DeviceId,
  ): Promise<Device | undefined> {
    const primary = this.devicesByServiceId.get(serviceId);
    if (deviceId === undefined || !primary || primary.deviceId === deviceId) {
      return primary;
    }
    if (primary.deviceId !== PRIMARY_DEVICE_ID) {
      return undefined;
    }
    return await this.getDevice(primary.number, deviceId);
  }

  public async getAllDevicesByServiceId(
    serviceId: ServiceIdString,
  ): Promise<ReadonlyArray<Device>> {
    const primary = this.devicesByServiceId.get(serviceId);
    if (!primary) {
      return [];
    }

    return this.devices.get(primary.number) || [];
  }

  public async getSenderCertificate(
    device: Device,
  ): Promise<SenderCertificate> {
    return generateSenderCertificate(this.certificate, {
      number: device.number,
      aci: device.aci,
      deviceId: device.deviceId,
      identityKey: await device.getIdentityKey(ServiceIdKind.ACI),
    });
  }

  public async getGroupCredentials(
    { aci, pni }: Device,
    range: CredentialsRange,
  ): Promise<Credentials> {
    const auth = new ServerZkAuthOperations(this.zkSecret);

    return this.issueCredentials(range, (redemptionTime) => {
      return auth.issueAuthCredentialWithPniZkc(
        Aci.parseFromServiceIdString(aci),
        Pni.parseFromServiceIdString(pni),
        redemptionTime,
      );
    });
  }

  public async verifyGroupCredentials(
    publicParams: Buffer,
    credential: Buffer,
  ): Promise<AuthCredentialPresentation> {
    const auth = new ServerZkAuthOperations(this.zkSecret);

    const groupParams = new GroupPublicParams(publicParams);
    const presentation = new AuthCredentialPresentation(credential);

    auth.verifyAuthCredentialPresentation(groupParams, presentation);

    // TODO(indutny): verify credential timestamp

    return presentation;
  }

  public async getCallLinkAuthCredentials(
    { aci }: Device,
    range: CredentialsRange,
  ): Promise<Credentials> {
    return this.issueCredentials(range, (redemptionTime) => {
      return CallLinkAuthCredentialResponse.issueCredential(
        Aci.parseFromServiceIdString(aci),
        redemptionTime,
        this.genericServerSecret,
      );
    });
  }

  public async issueExpiringProfileKeyCredential(
    { aci, profileKeyCommitment }: Device,
    request: ProfileKeyCredentialRequest,
  ): Promise<Buffer | undefined> {
    if (!profileKeyCommitment) {
      return undefined;
    }

    const today = getTodayInSeconds();

    const profile = new ServerZkProfileOperations(this.zkSecret);
    return profile
      .issueExpiringProfileKeyCredential(
        request,
        Aci.parseFromServiceIdString(aci),
        profileKeyCommitment,
        today + PROFILE_KEY_CREDENTIAL_EXPIRATION,
      )
      .serialize();
  }

  public async setBackupId(
    { aci }: Device,
    {
      messagesBackupAuthCredentialRequest,
      mediaBackupAuthCredentialRequest,
    }: SetBackupId,
  ): Promise<void> {
    this.backupAuthReqByAci.set(aci, {
      messages: new BackupAuthCredentialRequest(
        messagesBackupAuthCredentialRequest,
      ),
      media: new BackupAuthCredentialRequest(mediaBackupAuthCredentialRequest),
    });
  }

  public async setBackupKey(
    headers: BackupHeaders,
    { backupIdPublicKey }: SetBackupKey,
  ): Promise<void> {
    const publicKey = PublicKey.deserialize(backupIdPublicKey);
    const backupId = this.authenticateBackup(headers, publicKey);
    this.backupKeyById.set(backupId, publicKey);
    if (!this.backupCDNPasswordById.get(backupId)) {
      const password = crypto.randomBytes(16).toString('hex');
      this.backupCDNPasswordById.set(backupId, password);
    }
  }

  public async refreshBackup(headers: BackupHeaders): Promise<void> {
    this.authenticateBackup(headers);

    // No-op for tests
  }

  public async getBackupInfo(headers: BackupHeaders): Promise<BackupInfo> {
    const backupId = this.authenticateBackup(headers);

    return {
      cdn: 3,
      backupDir: backupId,
      mediaDir: 'media',
      backupName: 'backup',
    };
  }

  public async listBackupMedia(
    headers: BackupHeaders,
    { cursor, limit }: ListBackupMediaOptions,
  ): Promise<BackupMediaList> {
    const backupId = this.authenticateBackup(headers);

    let cursorData: BackupMediaCursor | undefined;
    let newCursor: string | undefined;
    if (cursor !== undefined) {
      cursorData = this.backupMediaCursorById.get(cursor);
    }
    if (cursorData === undefined) {
      newCursor = crypto.randomBytes(8).toString('hex');
      cursorData = {
        backupId,
        remainingMedia: this.backupMediaById.get(backupId)?.slice() ?? [],
      };
      this.backupMediaCursorById.set(newCursor, cursorData);
    } else {
      assert.strictEqual(cursorData.backupId, backupId);
    }

    const storedMediaObjects = cursorData.remainingMedia.slice(0, limit);

    // End of list
    if (storedMediaObjects.length < limit) {
      assert(newCursor !== undefined);

      this.backupMediaCursorById.delete(newCursor);
      newCursor = undefined;
    } else {
      cursorData.remainingMedia = cursorData.remainingMedia.slice(limit);
    }

    return {
      storedMediaObjects,
      backupDir: backupId,
      mediaDir: 'media',
      cursor: newCursor,
    };
  }

  public async getBackupMediaUploadForm(
    headers: BackupHeaders,
  ): Promise<AttachmentUploadForm> {
    this.authenticateBackup(headers);
    const form = await this.getAttachmentUploadForm('attachments', uuidv4());
    return form;
  }

  public async getBackupUploadForm(
    headers: BackupHeaders,
  ): Promise<AttachmentUploadForm> {
    const backupId = this.authenticateBackup(headers);
    const form = await this.getAttachmentUploadForm(
      'backups',
      `${backupId}/backup`,
    );
    return form;
  }

  public async backupMediaBatch(
    headers: BackupHeaders,
    batch: BackupMediaBatch,
  ): Promise<BackupMediaBatchResult> {
    const backupId = this.authenticateBackup(headers);
    const responses = await this.backupTransitAttachments(backupId, batch);
    return { responses };
  }

  public async getBackupCDNAuth(
    headers: BackupHeaders,
  ): Promise<Record<string, string>> {
    const backupId = this.authenticateBackup(headers);
    const password = this.backupCDNPasswordById.get(backupId);
    assert(password !== undefined);

    const basic = Buffer.from(`${backupId}:${password}`);
    const authorization = `Basic ${basic.toString('base64')}`;

    return {
      authorization,
    };
  }

  public async authorizeBackupCDN(
    backupId: string,
    password: string,
  ): Promise<boolean> {
    const expected = this.backupCDNPasswordById.get(backupId);
    if (expected === undefined) {
      return false;
    }

    if (!crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(password))) {
      return false;
    }

    return true;
  }

  public async getBackupCredentials(
    { aci, backupLevel }: Device,
    range: CredentialsRange,
  ): Promise<BackupCredentials | undefined> {
    const req = this.backupAuthReqByAci.get(aci);
    if (req === undefined) {
      return undefined;
    }

    const messages = this.issueCredentials(range, (redemptionTime) => {
      return req.messages.issueCredential(
        redemptionTime,
        BackupLevel.Free,
        BackupCredentialType.Messages,
        this.backupServerSecret,
      );
    });

    const media = this.issueCredentials(range, (redemptionTime) => {
      return req.media.issueCredential(
        redemptionTime,
        backupLevel,
        BackupCredentialType.Media,
        this.backupServerSecret,
      );
    });

    return {
      messages,
      media,
    };
  }

  protected async onNewBackupMediaObject(
    backupId: string,
    media: BackupMediaObject,
  ): Promise<void> {
    let list = this.backupMediaById.get(backupId);
    if (list === undefined) {
      list = [];
      this.backupMediaById.set(backupId, list);
    }
    list.push(media);
  }

  protected abstract backupTransitAttachments(
    backupId: string,
    batch: BackupMediaBatch,
  ): Promise<Array<BackupMediaBatchResponse>>;

  public abstract getTransferArchive(
    device: Device,
  ): Promise<TransferArchiveResponse>;

  public abstract isUnregistered(serviceId: ServiceIdString): boolean;

  public abstract isSendRateLimited(options: IsSendRateLimitedOptions): boolean;

  public abstract getResponseForChallenges(): ChallengeResponse | undefined;

  //
  // Private
  //

  protected set certificate(value: ServerCertificate) {
    if (this.privCertificate) {
      throw new Error('Certificate already set');
    }
    this.privCertificate = value;
  }

  protected get certificate(): ServerCertificate {
    if (!this.privCertificate) {
      throw new Error('Certificate not set');
    }
    return this.privCertificate;
  }

  protected set genericServerSecret(value: GenericServerSecretParams) {
    if (this.privGenericServerSecret) {
      throw new Error('zkgroup generic secret already set');
    }
    this.privGenericServerSecret = value;
  }

  protected get genericServerSecret(): GenericServerSecretParams {
    if (!this.privGenericServerSecret) {
      throw new Error('zkgroup generic secret not set');
    }
    return this.privGenericServerSecret;
  }

  protected set backupServerSecret(value: GenericServerSecretParams) {
    if (this.privBackupServerSecret) {
      throw new Error('zkgroup backup secret already set');
    }
    this.privBackupServerSecret = value;
  }

  protected get backupServerSecret(): GenericServerSecretParams {
    if (!this.privBackupServerSecret) {
      throw new Error('zkgroup backup secret not set');
    }
    return this.privBackupServerSecret;
  }

  protected set zkSecret(value: ServerSecretParams) {
    if (this.privZKSecret) {
      throw new Error('zkgroup secret already set');
    }
    this.privZKSecret = value;
  }

  protected get zkSecret(): ServerSecretParams {
    if (!this.privZKSecret) {
      throw new Error('zkgroup secret not set');
    }
    return this.privZKSecret;
  }

  private async sendQueue(device: Device, socket: WebSocket): Promise<void> {
    let queue = this.messageQueue.get(device);
    if (queue) {
      this.messageQueue.delete(device);
    } else {
      queue = [];
    }

    debug('sending queued %d messages to %s', queue.length, device.debugId);
    await Promise.all(
      queue.map(async (entry) => {
        const { message, resolve, reject } = entry;

        try {
          await socket.sendMessage(message);
        } catch (error) {
          assert(error instanceof Error);
          reject(error);
          return;
        }

        resolve();
      }),
    );

    debug('queue for %s is empty', device.debugId);
    await socket.sendMessage('empty');
  }

  private issueCredentials(
    { from, to }: CredentialsRange,
    issueOne: (redemptionTime: number) => SerializableCredential,
  ): Credentials {
    const today = getTodayInSeconds();
    if (
      from > to ||
      from < today ||
      to > today + DAY_IN_SECONDS * MAX_GROUP_CREDENTIALS_DAYS
    ) {
      throw new Error('Invalid redemption range');
    }

    const result: Credentials = [];

    for (
      let redemptionTime = from;
      redemptionTime <= to;
      redemptionTime += DAY_IN_SECONDS
    ) {
      result.push({
        credential: issueOne(redemptionTime).serialize().toString('base64'),
        redemptionTime,
      });
    }
    return result;
  }

  private authenticateBackup(
    headers: BackupHeaders,
    newPublicKey?: PublicKey,
  ): string {
    const presentation = new BackupAuthCredentialPresentation(
      headers['x-signal-zk-auth'],
    );
    presentation.verify(this.backupServerSecret);

    // Backup id is used in urls, so encode it properly
    const backupId = presentation.getBackupId().toString('base64url');

    const validatingKey = this.backupKeyById.get(backupId) || newPublicKey;
    if (!validatingKey) {
      throw new Error('No backup public key to validate against');
    }

    const isValid = validatingKey.verify(
      headers['x-signal-zk-auth'],
      headers['x-signal-zk-auth-signature'],
    );
    if (!isValid) {
      throw new Error('Invalid signature');
    }

    return backupId;
  }
}
