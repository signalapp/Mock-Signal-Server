// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import assert from 'assert';
import crypto from 'crypto';
import Long from 'long';
import { v4 as uuidv4 } from 'uuid';
import createDebug from 'debug';
import { SenderCertificate } from '@signalapp/libsignal-client';
import {
  AuthCredentialPresentation,
  GroupPublicParams,
  PniCredentialPresentation,
  ProfileKeyCredentialRequest,
  ProfileKeyCredentialResponse,
  ServerSecretParams,
  ServerZkAuthOperations,
  ServerZkProfileOperations,
} from '@signalapp/libsignal-client/zkgroup';

import { signalservice as Proto } from '../../protos/compiled';
import {
  ServerCertificate,
  generateSenderCertificate,
} from '../crypto';
import { Device, DeviceKeys } from '../data/device';
import {
  ATTACHMENT_PREFIX,
  MAX_GROUP_CREDENTIALS_DAYS,
  PRIMARY_DEVICE_ID,
} from '../constants';
import {
  AttachmentId,
  DeviceId,
  ProvisioningCode,
  RegistrationId,
  UUID,
} from '../types';
import { getEpochDay } from '../util';
import { JSONMessage } from '../data/json.d';
import { ServerGroup } from './group';

export enum EnvelopeType {
  CipherText = 'CipherText',
  PreKey = 'PreKey',
  SealedSender = 'SealedSender',
  SenderKey = 'SenderKey',
}

export type ProvisioningResponse = Readonly<{
  envelope: Buffer;
}>;

export type GroupCredentialsRange = Readonly<{
  from: number;
  to: number;
}>;

export type StorageCredentials = Readonly<{
  username: string;
  password: string;
}>;

export type GroupCredentials = Array<{
  credential: string;
  redemptionTime: number;
}>;

export type PreparedMultiDeviceMessage = ReadonlyArray<[ Device, JSONMessage ]>;

export type RegisterDeviceOptions = Readonly<{
  uuid: UUID;
  pni: UUID;
  number: string;
  registrationId: RegistrationId;
}>

export type PrepareMultiDeviceMessageResult = Readonly<{
  status: 'stale';
  staleDevices: ReadonlyArray<number>;
} | {
  status: 'incomplete';
  missingDevices: ReadonlyArray<number>;
  extraDevices: ReadonlyArray<number>;
} | {
  status: 'unknown';
} | {
  status: 'ok';
  result: PreparedMultiDeviceMessage;
}>;

export type StorageWriteResult = Readonly<{
  updated: false;
  manifest: Proto.IStorageManifest;
  error?: void;
} | {
  updated: true;
  manifest?: void;
  error?: void;
} | {
  updated?: void;
  error: string;
}>;

interface WebSocket {
  sendMessage(message: Buffer | 'empty'): Promise<void>;
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

const debug = createDebug('mock:server:base');

// NOTE: This class is currently extended only by src/api/server.ts
export abstract class Server {
  private readonly devices = new Map<string, Array<Device>>();
  private readonly devicesByUUID = new Map<UUID, Device>();
  private readonly usedUUIDs = new Set<string>();
  private readonly devicesByAuth = new Map<string, AuthEntry>();
  private readonly storageAuthByUsername = new Map<string, StorageAuthEntry>();
  private readonly storageAuthByDevice = new Map<Device, StorageAuthEntry>();
  private readonly storageManifestByUuid =
    new Map<UUID, Proto.IStorageManifest>();
  private readonly storageItemsByUuid =
    new Map<UUID, Map<string, Buffer>>();
  private readonly provisioningCodes =
    new Map<string, Map<ProvisioningCode, UUID>>();
  private readonly attachments = new Map<AttachmentId, Buffer>();
  private readonly webSockets = new Map<Device, Set<WebSocket>>();
  private readonly messageQueue =
    new WeakMap<Device, Array<MessageQueueEntry>>();
  private readonly groups = new Map<string, ServerGroup>();
  protected privCertificate: ServerCertificate | undefined;
  protected privZKSecret: ServerSecretParams | undefined;

  //
  // Provisioning
  //

  public async generateUUID(): Promise<UUID> {
    let result: UUID;
    do {
      result = uuidv4();
    } while (this.usedUUIDs.has(result) || this.devicesByUUID.has(result));
    this.usedUUIDs.add(result);
    return result;
  }

  public async releaseUUID(uuid: UUID): Promise<void> {
    if (this.devicesByUUID.has(uuid)) {
      assert.ok(!this.usedUUIDs.has(uuid));
      throw new Error('Can\'t release UUID');
    }
    this.usedUUIDs.delete(uuid);
  }

  public async generateRegistrationId(): Promise<RegistrationId> {
    return Math.max(1, (Math.random() * 0x4000) | 0);
  }

  public abstract getProvisioningResponse(
    uuid: UUID
  ): Promise<ProvisioningResponse>;

  public async registerDevice({
    uuid,
    pni,
    number,
    registrationId,
  }: RegisterDeviceOptions): Promise<Device> {
    if (!this.usedUUIDs.has(uuid)) {
      throw new Error('Use generateUUID() to create new UUID');
    }

    let list = this.devices.get(number);
    if (!list) {
      list = [];
      this.devices.set(number, list);
    }
    const deviceId = list.length + 1;
    const isPrimary = deviceId === PRIMARY_DEVICE_ID;

    const device = new Device({
      uuid,
      pni,
      number,
      deviceId,
      registrationId,
    });

    if (isPrimary) {
      assert(!this.devicesByUUID.has(uuid), 'Duplicate primary device');
      this.devicesByUUID.set(uuid, device);
    }
    list.push(device);

    debug('registered device number=%j uuid=%s', number, uuid);
    return device;
  }

  // Called from primary device
  public async getProvisioningCode(
    uuid: UUID,
    number: string,
  ): Promise<ProvisioningCode> {
    let entry = this.provisioningCodes.get(number);
    if (!entry) {
      entry = new Map<ProvisioningCode, UUID>();
      this.provisioningCodes.set(number, entry);
    }
    let code: ProvisioningCode;
    do {
      code = crypto.randomBytes(8).toString('hex');
    } while (entry.has(code));
    entry.set(code, uuid);
    return code;
  }

  // Called from secondary device
  public async provisionDevice(
    number: string,
    password: string,
    provisioningCode: ProvisioningCode,
    registrationId: RegistrationId,
  ): Promise<Device> {
    const entry = this.provisioningCodes.get(number);
    if (!entry) {
      throw new Error('Invalid number for provisioning');
    }

    const uuid = entry.get(provisioningCode);
    if (!uuid) {
      throw new Error('Invalid provisioning code');
    }
    entry.delete(provisioningCode);

    const [ primary ] = this.devices.get(number) || [];
    assert(primary !== undefined, 'Missing primary device when provisioning');

    const device = await this.registerDevice({
      uuid: primary.uuid,
      pni: primary.pni,
      number,
      registrationId,
    });

    const username = `${number}.${device.deviceId}`;

    // This is awkward, but WebSockets use it.
    const secondUsername = `${device.uuid}.${device.deviceId}`;

    // Add auth only after successfully registering the device
    assert(
      !this.devicesByAuth.has(username) &&
      !this.devicesByAuth.has(secondUsername),
      'Duplicate username in `provisionDevice`');
    const authEntry = {
      password,
      device,
    };
    this.devicesByAuth.set(username, authEntry);
    this.devicesByAuth.set(secondUsername, authEntry);

    debug('provisioned device number=%j uuid=%j', number, uuid);
    return device;
  }

  public async updateDeviceKeys(
    device: Device,
    keys: DeviceKeys,
  ): Promise<void> {
    debug('setting device=%s keys', device.debugId);
    await device.setKeys(keys);
  }

  //
  // Auth
  //

  async auth(username: string, password: string): Promise<Device | undefined> {
    const entry = this.devicesByAuth.get(username);
    if (!entry) {
      debug('auth failed, username=%j is unknown', username);
      return;
    }
    if (entry.password !== password) {
      debug('auth failed, invalid login/password %j:%j', username, password);
    }
    return entry.device;
  }

  //
  // CDN
  //

  async storeAttachment(attachment: Buffer): Promise<AttachmentId> {
    const id = ATTACHMENT_PREFIX +
      crypto.createHash('sha256').update(attachment).digest('hex');
    this.attachments.set(id, attachment);
    return id;
  }

  async fetchAttachment(id: AttachmentId): Promise<Buffer | undefined> {
    return this.attachments.get(id);
  }

  //
  // Messages
  //

  public async prepareMultiDeviceMessage(
    source: Device | undefined,
    targetUUID: UUID,
    messages: ReadonlyArray<JSONMessage>,
  ): Promise<PrepareMultiDeviceMessageResult> {
    const devices = await this.getAllDevicesByUUID(targetUUID);
    if (devices.length === 0) {
      return { status: 'unknown' };
    }

    const deviceById = new Map<DeviceId, Device>();
    for (const device of devices) {
      deviceById.set(device.deviceId, device);
    }

    const result = new Array<[ Device, JSONMessage ]>();

    const extraDevices = new Set<DeviceId>();
    const staleDevices = new Set<DeviceId>();
    for (const message of messages) {
      const {
        destinationDeviceId,
        destinationRegistrationId,
      } = message;

      const target = deviceById.get(destinationDeviceId);
      if (!target) {
        extraDevices.add(destinationDeviceId);
        continue;
      }

      deviceById.delete(destinationDeviceId);

      if (target.registrationId !== destinationRegistrationId) {
        staleDevices.add(destinationDeviceId);
        continue;
      }

      result.push([ target, message ]);
    }

    if (source && source.uuid === targetUUID) {
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

    return { status: 'ok', result };
  }

  public async handlePreparedMultiDeviceMessage(
    source: Device | undefined,
    prepared: PreparedMultiDeviceMessage,
  ): Promise<void> {
    for (const [ target, message ] of prepared) {
      let envelopeType: EnvelopeType;
      if (message.type === Proto.Envelope.Type.CIPHERTEXT) {
        envelopeType = EnvelopeType.CipherText;
      } else if (message.type === Proto.Envelope.Type.PREKEY_BUNDLE) {
        envelopeType = EnvelopeType.PreKey;
      } else if (message.type === Proto.Envelope.Type.UNIDENTIFIED_SENDER) {
        envelopeType = EnvelopeType.SealedSender;
      } else {
        throw new Error(`Unsupported envelope type: ${message.type}`);
      }

      await this.handleMessage(
        source,
        envelopeType,
        target,
        Buffer.from(message.content, 'base64'),
      );
    }
  }

  public abstract handleMessage(
    source: Device | undefined,
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
  public async send(
    target: Device,
    message: Buffer,
  ): Promise<void> {
    const sockets = this.webSockets.get(target);
    if (sockets) {
      debug(
        'sending message to %d sockets of %s',
        sockets.size,
        target.debugId);
      let success = false;
      await Promise.all<void>(Array.from(sockets).map(async (socket) => {
        try {
          await socket.sendMessage(message);
          success = true;
        } catch (error) {
          assert(error instanceof Error);
          debug('failed to send message to socket of %s, error %s',
            target.debugId, error.message);
        }
      }));

      // At least one send should succeed, if not - queue
      if (success) {
        return;
      }

      debug(
        'message couldn\'t be sent to %s',
        sockets.size,
        target.debugId);
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
    return this.storageManifestByUuid.get(device.uuid);
  }

  public async applyStorageWrite(
    device: Device,
    {
      manifest,
      clearAll,
      insertItem,
      deleteKey,
    }: Proto.IWriteOperation,
    shouldNotify = true,
  ): Promise<StorageWriteResult> {
    if (!manifest) {
      return { error: 'missing `writeOperation.manifest`' };
    }

    if (!manifest.version) {
      return {
        error: 'not updating storage manifest, ' +
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
    this.storageManifestByUuid.set(device.uuid, manifest);

    if (shouldNotify) {
      await this.onStorageManifestUpdate(device, manifest.version);
    }

    return { updated: true };
  }

  private async clearStorageItems(device: Device): Promise<void> {
    this.storageItemsByUuid.get(device.uuid)?.clear();
  }

  private async setStorageItem(
    device: Device,
    key: Buffer,
    value: Buffer,
  ): Promise<void> {
    let map = this.storageItemsByUuid.get(device.uuid);
    if (!map) {
      map = new Map();
      this.storageItemsByUuid.set(device.uuid, map);
    }

    map.set(key.toString('hex'), value);
  }

  public async getStorageItem(
    device: Device,
    key: Buffer,
  ): Promise<Buffer | undefined> {
    const map = this.storageItemsByUuid.get(device.uuid);
    if (!map) {
      return undefined;
    }

    return map.get(key.toString('hex'));
  }

  public async getStorageItems(
    device: Device,
    keys: ReadonlyArray<Buffer>,
  ): Promise<Array<Proto.IStorageItem> | undefined> {
    const result = new Array<Proto.IStorageItem>();

    await Promise.all(keys.map(async (key) => {
      const value = await this.getStorageItem(device, key);
      if (value !== undefined) {
        result.push({ key, value });
      }
    }));

    return result;
  }

  public async deleteStorageItem(
    device: Device,
    key: Buffer,
  ): Promise<void> {
    const map = this.storageItemsByUuid.get(device.uuid);
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

  public async getDeviceByUUID(
    uuid: UUID,
    deviceId?: DeviceId,
  ): Promise<Device | undefined> {
    const primary = this.devicesByUUID.get(uuid);
    if (deviceId === undefined || !primary || primary.deviceId === deviceId) {
      return primary;
    }
    if (primary.deviceId !== PRIMARY_DEVICE_ID) {
      return undefined;
    }
    return await this.getDevice(primary.number, deviceId);
  }

  public async getAllDevicesByUUID(
    uuid: UUID,
  ): Promise<ReadonlyArray<Device>> {
    const primary = this.devicesByUUID.get(uuid);
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
      uuid: device.uuid,
      deviceId: device.deviceId,
      identityKey: await device.getIdentityKey(),
    });
  }

  public async getGroupCredentials(
    uuid: UUID,
    { from, to }: GroupCredentialsRange,
  ): Promise<GroupCredentials> {
    const today = getEpochDay();
    if (from > to || from < today || to > today + MAX_GROUP_CREDENTIALS_DAYS) {
      throw new Error('Invalid redemption range');
    }

    const auth = new ServerZkAuthOperations(this.zkSecret);
    const result: GroupCredentials = [];
    for (let redemptionTime = from; redemptionTime <= to; redemptionTime++) {
      result.push({
        credential: auth.issueAuthCredential(uuid, redemptionTime)
          .serialize().toString('base64'),
        redemptionTime,
      });
    }
    return result;
  }

  public async verifyGroupACICredentials(
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

  public async verifyGroupPNICredentials(
    publicParams: Buffer,
    credential: Buffer,
  ): Promise<PniCredentialPresentation> {
    const profile = new ServerZkProfileOperations(this.zkSecret);

    const groupParams = new GroupPublicParams(publicParams);
    const presentation = new PniCredentialPresentation(credential);

    profile.verifyPniCredentialPresentation(groupParams, presentation);

    // TODO(indutny): verify credential timestamp

    return presentation;
  }

  public async issueProfileKeyCredential(
    { uuid, profileKeyCommitment }: Device,
    request: ProfileKeyCredentialRequest,
  ): Promise<ProfileKeyCredentialResponse | undefined> {
    if (!profileKeyCommitment) {
      return undefined;
    }

    const profile = new ServerZkProfileOperations(this.zkSecret);
    return profile.issueProfileKeyCredential(
      request,
      uuid,
      profileKeyCommitment,
    );
  }

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
    await Promise.all(queue.map(async (entry) => {
      const { message, resolve, reject } = entry;

      try {
        await socket.sendMessage(message);
      } catch (error) {
        assert(error instanceof Error);
        reject(error);
        return;
      }

      resolve();
    }));

    debug('queue for %s is empty', device.debugId);
    await socket.sendMessage('empty');
  }
}
