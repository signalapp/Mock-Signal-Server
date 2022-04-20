// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import assert from 'assert';
import fs from 'fs';
import Long from 'long';
import path from 'path';
import https, { ServerOptions } from 'https';
import { AddressInfo } from 'net';
import { parse as parseURL } from 'url';
import {
  PrivateKey,
  PublicKey,
} from '@signalapp/libsignal-client';
import { ServerSecretParams } from '@signalapp/libsignal-client/zkgroup';
import createDebug from 'debug';
import WebSocket from 'ws';
import { run } from 'micro';

import {
  attachmentToPointer,
} from '../data/attachment';
import {
  PRIMARY_DEVICE_ID,
} from '../constants';
import {
  ProvisioningCode,
  RegistrationId,
  UUID,
  UUIDKind,
} from '../types';
import {
  serializeContacts,
} from '../data/contacts';
import {
  Group as GroupData,
} from '../data/group';
import {
  encryptAttachment,
  encryptProvisionMessage,
  generateServerCertificate,
} from '../crypto';
import { signalservice as Proto } from '../../protos/compiled';
import {
  Server as BaseServer,
  EnvelopeType,
  ModifyGroupOptions,
  ProvisioningResponse,
} from '../server/base';
import { Device, DeviceKeys } from '../data/device';
import { PromiseQueue, generateRandomE164 } from '../util';

import { createHandler as createHTTPHandler } from '../server/http';
import { Connection as WSConnection } from '../server/ws';

import { PrimaryDevice } from './primary-device';

type TrustRoot = Readonly<{
  privateKey: string;
  publicKey: string;
}>

type ZKParams = Readonly<{
  secretParams: string;
  publicParams: string;
}>

type StrictConfig = Readonly<{
  trustRoot: TrustRoot;
  zkParams: ZKParams;
  https: ServerOptions;
  timeout: number;
  maxStorageReadKeys?: number;
}>

export type Config = Readonly<{
  trustRoot?: TrustRoot;
  zkParams?: ZKParams;
  https?: ServerOptions;
  timeout?: number;
  maxStorageReadKeys?: number;
}>

export type CreatePrimaryDeviceOptions = Readonly<{
  profileName: string;
  initialPreKeyCount?: number;
  contacts?: ReadonlyArray<PrimaryDevice>;
}>

export type PendingProvision = {
  complete(response: PendingProvisionResponse): Promise<Device>;
}

export type PendingProvisionResponse = Readonly<{
  provisionURL: string;
  primaryDevice: PrimaryDevice;
}>

const debug = createDebug('mock:server:mock');

const CERTS_DIR = path.join(__dirname, '..', '..', 'certs');

const CERT = fs.readFileSync(path.join(CERTS_DIR, 'full-cert.pem'));
const KEY = fs.readFileSync(path.join(CERTS_DIR, 'key.pem'));
const TRUST_ROOT: TrustRoot = JSON.parse(
  fs.readFileSync(path.join(CERTS_DIR, 'trust-root.json')).toString(),
);
const ZK_PARAMS: ZKParams = JSON.parse(
  fs.readFileSync(path.join(CERTS_DIR, 'zk-params.json')).toString(),
);

const DEFAULT_API_TIMEOUT = 60000;

export class Server extends BaseServer {
  private readonly config: StrictConfig;

  private readonly trustRoot: PrivateKey;
  private readonly primaryDevices = new Map<string, PrimaryDevice>();
  private readonly knownNumbers = new Set<string>();
  private https: https.Server | undefined;
  private emptyAttachment: Proto.IAttachmentPointer | undefined;

  private provisionQueue: PromiseQueue<PendingProvision>;
  private provisionResultQueueByCode =
    new Map<ProvisioningCode, PromiseQueue<Device>>();
  private provisionResultQueueByKey = new Map<string, PromiseQueue<Device>>();
  private manifestQueueByUuid = new Map<UUID, PromiseQueue<number>>();
  private groupQueueById = new Map<string, PromiseQueue<number>>();

  constructor(config: Config = {}) {
    super();

    this.config = {
      timeout: DEFAULT_API_TIMEOUT,
      trustRoot: TRUST_ROOT,
      zkParams: ZK_PARAMS,
      ...config,

      https: {
        key: KEY,
        cert: CERT,
        ...(config.https || {}),
      },
    };

    const trustPrivate = Buffer.from(
      this.config.trustRoot.privateKey, 'base64');
    this.trustRoot = PrivateKey.deserialize(trustPrivate);

    const zkSecret = Buffer.from(
      this.config.zkParams.secretParams, 'base64');
    this.zkSecret = new ServerSecretParams(zkSecret);

    this.certificate = generateServerCertificate(this.trustRoot);

    this.provisionQueue = this.createQueue();
  }

  public async listen(port: number, host?: string): Promise<void> {
    if (this.https) {
      throw new Error('Already listening');
    }

    const emptyData = encryptAttachment(Buffer.alloc(0));
    const emptyCDNKey = await this.storeAttachment(emptyData.blob);

    this.emptyAttachment = attachmentToPointer(
      emptyCDNKey,
      emptyData);

    const httpHandler = createHTTPHandler(this);

    const server = https.createServer(this.config.https || {}, (req, res) => {
      run(req, res, httpHandler);
    });

    const wss = new WebSocket.Server({ server });

    wss.on('connection', (ws, request) => {
      const conn = new WSConnection(request, ws, this);

      conn.start().catch((error) => {
        ws.close();
        debug('Websocket handling error', error.stack);
      });
    });

    this.https = server;

    return await new Promise((resolve) => {
      server.listen(port, host, () => resolve());
    });
  }

  public async close(): Promise<void> {
    const https = this.https;
    if (!https) {
      throw new Error('Not listening');
    }

    debug('closing server');

    await new Promise((resolve) => https.close(resolve));
  }

  public address(): AddressInfo {
    if (!this.https) {
      throw new Error('Not listening');
    }

    const result = this.https.address();
    if (!result || typeof result !== 'object' ){
      throw new Error('Invalid .address() result');
    }
    return result;
  }

  //
  // Various queues
  //

  public async waitForProvision(): Promise<PendingProvision> {
    return await this.provisionQueue.shift();
  }

  private async waitForStorageManifest(
    device: Device,
    afterVersion?: number,
  ): Promise<void> {
    let queue = this.manifestQueueByUuid.get(device.uuid);
    if (!queue) {
      queue = this.createQueue();
      this.manifestQueueByUuid.set(device.uuid, queue);
    }

    let version: number;
    do {
      version = await queue.shift();
    } while (afterVersion !== undefined && version <= afterVersion);
  }

  public async waitForGroupUpdate(group: GroupData): Promise<void> {
    let queue = this.groupQueueById.get(group.id);
    if (!queue) {
      queue = this.createQueue();
      this.groupQueueById.set(group.id, queue);
    }

    let version: number;
    do {
      version = await queue.shift();
    } while (version <= group.revision);
  }

  //
  // Helper methods
  //

  public async createPrimaryDevice({
    profileName,
    initialPreKeyCount,
    contacts = [],
  }: CreatePrimaryDeviceOptions): Promise<PrimaryDevice> {
    const number = await this.generateNumber();

    const uuid = await this.generateUUID();
    const pni = await this.generateUUID();
    const registrationId = await this.generateRegistrationId();
    const device = await this.registerDevice({
      uuid,
      pni,
      number,
      registrationId,
    });

    debug('creating primary device with uuid=%s registrationId=%d',
      uuid, registrationId);

    if (!this.emptyAttachment) {
      throw new Error('Mock#init must be called before starting the server');
    }

    const contactsAttachment = encryptAttachment(
      serializeContacts(contacts.map((device: PrimaryDevice) => {
        return device.toContact();
      })));
    const contactsCDNKey = await this.storeAttachment(contactsAttachment.blob);
    debug('contacts cdn key', contactsCDNKey);
    debug('groups cdn key', this.emptyAttachment.cdnKey);

    const primary = new PrimaryDevice(device, {
      profileName: profileName,
      contacts: attachmentToPointer(contactsCDNKey, contactsAttachment),
      groups: this.emptyAttachment,
      trustRoot: this.trustRoot.getPublicKey(),
      serverPublicParams: this.zkSecret.getPublicParams(),

      send: this.send.bind(this),
      getSenderCertificate: this.getSenderCertificate.bind(this, device),
      getDeviceByUUID: this.getDeviceByUUID.bind(this),
      issueProfileKeyCredential: this.issueProfileKeyCredential.bind(this),
      getGroup: this.getGroup.bind(this),
      createGroup: this.createGroup.bind(this),
      modifyGroup: this.modifyGroup.bind(this),
      waitForGroupUpdate: this.waitForGroupUpdate.bind(this),
      getStorageManifest: this.getStorageManifest.bind(this, device),
      getStorageItem: this.getStorageItem.bind(this, device),
      waitForStorageManifest: this.waitForStorageManifest.bind(this, device),
      applyStorageWrite: this.applyStorageWrite.bind(this, device),
    });
    await primary.init(initialPreKeyCount);

    this.primaryDevices.set(number, primary);
    this.primaryDevices.set(uuid, primary);

    debug('created primary device number=%s uuid=%s', number, uuid);

    return primary;
  }

  public async createSecondaryDevice(primary: PrimaryDevice): Promise<Device> {
    const registrationId = await this.generateRegistrationId();

    const device = await this.registerDevice({
      uuid: primary.device.uuid,
      pni: primary.device.pni,
      number: primary.device.number,
      registrationId,
    });

    for (const uuidKind of [ UUIDKind.ACI, UUIDKind.PNI ]) {
      await this.updateDeviceKeys(
        device,
        uuidKind,
        await primary.generateKeys(device, uuidKind),
      );
    }

    primary.addSecondaryDevice(device);

    return device;
  }

  //
  // Implement Server's abstract methods
  //

  public async getProvisioningResponse(
    uuid: UUID,
  ): Promise<ProvisioningResponse> {
    const responseQueue = this.createQueue<PendingProvisionResponse>();
    const resultQueue = this.createQueue<Device>();

    await this.provisionQueue.pushAndWait({
      complete: async (response) => {
        await responseQueue.pushAndWait(response);
        return await resultQueue.shift();
      },
    });

    const {
      // tsdevice:/?uuid=<uuid>&pub_key=<base64>
      provisionURL,
      primaryDevice,
    } = await responseQueue.shift();

    const query = parseURL(provisionURL, true).query || {};

    assert.strictEqual(query.uuid, uuid, 'UUID mismatch');
    if (!query.pub_key || Array.isArray(query.pub_key)) {
      throw new Error('Expected `pub_key` in provision URL');
    }

    const publicKey = PublicKey.deserialize(
      Buffer.from(query.pub_key, 'base64'));

    const aciIdentityKey = await primaryDevice.getIdentityKey(UUIDKind.ACI);
    const pniIdentityKey = await primaryDevice.getIdentityKey(UUIDKind.PNI);
    const provisioningCode = await this.getProvisioningCode(
      uuid, primaryDevice.device.number);

    this.provisionResultQueueByCode.set(provisioningCode, resultQueue);

    const envelopeData = Proto.ProvisionMessage.encode({
      aciIdentityKeyPrivate: aciIdentityKey.serialize(),
      aciIdentityKeyPublic: aciIdentityKey.getPublicKey().serialize(),
      pniIdentityKeyPrivate: pniIdentityKey.serialize(),
      pniIdentityKeyPublic: pniIdentityKey.getPublicKey().serialize(),
      number: primaryDevice.device.number,
      aci: primaryDevice.device.uuid,
      pni: primaryDevice.device.pni,
      provisioningCode,
      profileKey: primaryDevice.profileKey.serialize(),
      userAgent: primaryDevice.userAgent,
      readReceipts: true,
      // TODO(indutny): is it correct?
      ProvisioningVersion: Proto.ProvisioningVersion.CURRENT,
    }).finish();

    const { body, ephemeralKey } = encryptProvisionMessage(
      Buffer.from(envelopeData), publicKey);

    const envelope = Proto.ProvisionEnvelope.encode({
      publicKey: ephemeralKey,
      body,
    }).finish();

    return { envelope: Buffer.from(envelope) };
  }

  public async handleMessage(
    source: Device | undefined,
    uuidKind: UUIDKind,
    envelopeType: EnvelopeType,
    target: Device,
    encrypted: Buffer,
  ): Promise<void> {
    assert(
      source || envelopeType === EnvelopeType.SealedSender,
      'No source for non-sealed sender envelope',
    );

    debug('got message for %s.%d', target.uuid, target.deviceId);

    if (target.deviceId !== PRIMARY_DEVICE_ID) {
      debug('ignoring message, not primary');
      return;
    }

    const primary = this.primaryDevices.get(target.uuid);
    if (!primary) {
      debug('ignoring message, primary device not found');
      return;
    }

    await primary.handleEnvelope(source, uuidKind, envelopeType, encrypted);
  }

  //
  // Override `Server`'s methods to automatically pass keys to primary
  // devices.
  //
  // TODO(indutny): use popSingleUseKey() perhaps?
  //

  public override async updateDeviceKeys(
    device: Device,
    uuidKind: UUIDKind,
    keys: DeviceKeys,
  ): Promise<void> {
    await super.updateDeviceKeys(device, uuidKind, keys);

    const key = `${device.uuid}.${device.registrationId}.${uuidKind}`;

    // Device is marked as provisioned only once we have its keys
    const resultQueue = this.provisionResultQueueByKey.get(key);
    if (!resultQueue) {
      return;
    }
    this.provisionResultQueueByKey.delete(key);
    await resultQueue.pushAndWait(device);
  }

  public override async provisionDevice(
    number: string,
    password: string,
    provisioningCode: ProvisioningCode,
    registrationId: RegistrationId,
  ): Promise<Device> {
    const queue = this.provisionResultQueueByCode.get(provisioningCode);
    assert(
      queue !== undefined,
      `Missing provision result queue for code: ${provisioningCode}`);
    this.provisionResultQueueByCode.delete(provisioningCode);

    const device = await super.provisionDevice(
      number,
      password,
      provisioningCode,
      registrationId);

    const key = `${device.uuid}.${device.registrationId}.${UUIDKind.ACI}`;

    this.provisionResultQueueByKey.set(key, queue);

    const primary = this.primaryDevices.get(device.uuid);
    primary?.addSecondaryDevice(device);

    return device;
  }

  // Override `getStorageItems` to provide configurable limit for maximum
  // storage read keys.
  public override async getStorageItems(
    device: Device,
    keys: ReadonlyArray<Buffer>,
  ): Promise<Array<Proto.IStorageItem> | undefined> {
    if (
      this.config.maxStorageReadKeys !== undefined &&
      keys.length > this.config.maxStorageReadKeys) {
      debug('getStorageItems: requested more than max keys', device.debugId);
      return undefined;
    }

    return super.getStorageItems(device, keys);
  }

  // Override updateGroup to notify about group modifications
  public override async modifyGroup(
    options: ModifyGroupOptions,
  ): Promise<Proto.IGroupChange> {
    const { group } = options;
    debug('modifyGroup', group.id);

    const result = await super.modifyGroup(options);

    let queue = this.groupQueueById.get(group.id);
    if (!queue) {
      queue = this.createQueue();
      this.groupQueueById.set(group.id, queue);
    }

    queue.push(group.revision);

    return result;
  }

  protected async onStorageManifestUpdate(
    device: Device,
    version: Long,
  ): Promise<void> {
    debug('onStorageManifestUpdate', device.debugId);

    let queue = this.manifestQueueByUuid.get(device.uuid);
    if (!queue) {
      queue = this.createQueue();
      this.manifestQueueByUuid.set(device.uuid, queue);
    }

    queue.push(version.toNumber());
  }

  //
  // Private
  //

  private createQueue<T>(): PromiseQueue<T> {
    return new PromiseQueue({
      timeout: this.config.timeout,
    });
  }

  private async generateNumber(): Promise<string> {
    let number: string;
    do {
      number = generateRandomE164();
    } while (this.knownNumbers.has(number));
    this.knownNumbers.add(number);

    return number;
  }
}
