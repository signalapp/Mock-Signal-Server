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
  AciString,
  ProvisionIdString,
  ProvisioningCode,
  ServiceIdKind,
  ServiceIdString,
  untagPni,
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
  IsSendRateLimitedOptions,
  ModifyGroupOptions,
  ModifyGroupResult,
  ProvisionDeviceOptions,
  ProvisioningResponse,
} from '../server/base';
import { Device, DeviceKeys } from '../data/device';
import {
  PromiseQueue,
  generateRandomE164,
  generateRegistrationId,
} from '../util';

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
  contacts?: ReadonlyArray<PrimaryDevice>;
  contactsWithoutProfileKey?: ReadonlyArray<PrimaryDevice>;
}>

export type PendingProvision = {
  complete(response: PendingProvisionResponse): Promise<Device>;
}

export type PendingProvisionResponse = Readonly<{
  provisionURL: string;
  primaryDevice: PrimaryDevice;
}>

export type RateLimitOptions = Readonly<{
  source: ServiceIdString;
  target: ServiceIdString;
}>;

type ProvisionResultQueue = Readonly<{
  seenServiceIdKinds: Set<ServiceIdKind>;
  promiseQueue: PromiseQueue<Device>;
}>;

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
    new Map<ProvisioningCode, ProvisionResultQueue>();
  private provisionResultQueueByKey = new Map<string, ProvisionResultQueue>();
  private manifestQueueByAci = new Map<AciString, PromiseQueue<number>>();
  private groupQueueById = new Map<string, PromiseQueue<number>>();
  private rateLimitCountByPair =
    new Map<`${ServiceIdString}:${ServiceIdString}`, number>();
  private unregisteredServiceIds = new Set<ServiceIdString>();

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
    let queue = this.manifestQueueByAci.get(device.aci);
    if (!queue) {
      queue = this.createQueue();
      this.manifestQueueByAci.set(device.aci, queue);
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
    contacts = [],
    contactsWithoutProfileKey = [],
  }: CreatePrimaryDeviceOptions): Promise<PrimaryDevice> {
    const number = await this.generateNumber();

    const registrationId = await generateRegistrationId();
    const pniRegistrationId = await generateRegistrationId();
    const device = await this.registerDevice({
      number,
      registrationId,
      pniRegistrationId,
    });

    const { aci } = device;

    debug('creating primary device with aci=%s registrationId=%d',
      aci, registrationId);

    if (!this.emptyAttachment) {
      throw new Error('Mock#init must be called before starting the server');
    }

    const contactsAttachment = encryptAttachment(
      serializeContacts([
        ...contacts.map((device) => device.toContact()),
        ...contactsWithoutProfileKey.map((device) => device.toContact({
          includeProfileKey: false,
        })),
      ]),
    );
    const contactsCDNKey = await this.storeAttachment(contactsAttachment.blob);
    debug('contacts cdn key', contactsCDNKey);
    debug('groups cdn key', this.emptyAttachment.cdnKey);

    const primary = new PrimaryDevice(device, {
      profileName: profileName,
      contacts: attachmentToPointer(contactsCDNKey, contactsAttachment),
      trustRoot: this.trustRoot.getPublicKey(),
      serverPublicParams: this.zkSecret.getPublicParams(),

      generateNumber: this.generateNumber.bind(this),
      generatePni: this.generatePni.bind(this),
      changeDeviceNumber: this.changeDeviceNumber.bind(this),
      send: this.send.bind(this),
      getSenderCertificate: this.getSenderCertificate.bind(this, device),
      getDeviceByServiceId: this.getDeviceByServiceId.bind(this),
      issueExpiringProfileKeyCredential:
        this.issueExpiringProfileKeyCredential.bind(this),
      getGroup: this.getGroup.bind(this),
      createGroup: this.createGroup.bind(this),
      modifyGroup: this.modifyGroup.bind(this),
      waitForGroupUpdate: this.waitForGroupUpdate.bind(this),
      getStorageManifest: this.getStorageManifest.bind(this, device),
      getStorageItem: this.getStorageItem.bind(this, device),
      getAllStorageKeys: this.getAllStorageKeys.bind(this, device),
      waitForStorageManifest: this.waitForStorageManifest.bind(this, device),
      applyStorageWrite: this.applyStorageWrite.bind(this, device),
    });
    await primary.init();

    this.primaryDevices.set(primary.device.number, primary);
    this.primaryDevices.set(primary.device.aci, primary);

    debug(
      'created primary device number=%s aci=%s',
      primary.device.number,
      primary.device.aci,
    );

    return primary;
  }

  public async createSecondaryDevice(primary: PrimaryDevice): Promise<Device> {
    const registrationId = await generateRegistrationId();
    const pniRegistrationId = await generateRegistrationId();

    const device = await this.registerDevice({
      primary: primary.device,
      registrationId,
      pniRegistrationId,
    });

    for (const serviceIdKind of [ ServiceIdKind.ACI, ServiceIdKind.PNI ]) {
      await this.updateDeviceKeys(
        device,
        serviceIdKind,
        await primary.generateKeys(device, serviceIdKind),
      );
    }

    primary.addSecondaryDevice(device);

    return device;
  }

  public unregister(
    primary: PrimaryDevice,
    serviceIdKind = ServiceIdKind.ACI,
  ): void {
    this.unregisteredServiceIds.add(
      primary.device.getServiceIdByKind(serviceIdKind),
    );
  }

  public register(
    primary: PrimaryDevice,
    serviceIdKind = ServiceIdKind.ACI,
  ): void {
    this.unregisteredServiceIds.delete(
      primary.device.getServiceIdByKind(serviceIdKind),
    );
  }

  public rateLimit({ source, target }: RateLimitOptions): void {
    this.rateLimitCountByPair.set(`${source}:${target}`, 0);
  }

  public stopRateLimiting({
    source,
    target,
  }: RateLimitOptions): number | undefined {
    const key: `${ServiceIdString}:${ServiceIdString}` = `${source}:${target}`;
    const existing = this.rateLimitCountByPair.get(key);
    this.rateLimitCountByPair.delete(key);
    return existing;
  }

  //
  // Implement Server's abstract methods
  //

  public async getProvisioningResponse(
    id: ProvisionIdString,
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

    assert.strictEqual(query.uuid, id, 'id mismatch');
    if (!query.pub_key || Array.isArray(query.pub_key)) {
      throw new Error('Expected `pub_key` in provision URL');
    }

    const publicKey = PublicKey.deserialize(
      Buffer.from(query.pub_key, 'base64'));

    const aciIdentityKey = await primaryDevice.getIdentityKey(
      ServiceIdKind.ACI,
    );
    const pniIdentityKey = await primaryDevice.getIdentityKey(
      ServiceIdKind.PNI,
    );
    const provisioningCode = await this.getProvisioningCode(
      id, primaryDevice.device.number);

    this.provisionResultQueueByCode.set(provisioningCode, {
      seenServiceIdKinds: new Set(),
      promiseQueue: resultQueue,
    });

    const envelopeData = Proto.ProvisionMessage.encode({
      aciIdentityKeyPrivate: aciIdentityKey.serialize(),
      aciIdentityKeyPublic: aciIdentityKey.getPublicKey().serialize(),
      pniIdentityKeyPrivate: pniIdentityKey.serialize(),
      pniIdentityKeyPublic: pniIdentityKey.getPublicKey().serialize(),
      number: primaryDevice.device.number,
      aci: primaryDevice.device.aci,
      pni: untagPni(primaryDevice.device.pni),
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
    serviceIdKind: ServiceIdKind,
    envelopeType: EnvelopeType,
    target: Device,
    encrypted: Buffer,
  ): Promise<void> {
    assert(
      source || envelopeType === EnvelopeType.SealedSender,
      'No source for non-sealed sender envelope',
    );

    debug('got message for %s.%d', target.aci, target.deviceId);

    if (target.deviceId !== PRIMARY_DEVICE_ID) {
      debug('ignoring message, not primary');
      return;
    }

    const primary = this.primaryDevices.get(target.aci);
    if (!primary) {
      debug('ignoring message, primary device not found');
      return;
    }

    await primary.handleEnvelope(
      source,
      serviceIdKind,
      envelopeType,
      encrypted,
    );
  }

  public isUnregistered(serviceId: ServiceIdString): boolean {
    return this.unregisteredServiceIds.has(serviceId);
  }

  public isSendRateLimited({
    source,
    target,
  }: IsSendRateLimitedOptions): boolean {
    const key: `${ServiceIdString}:${ServiceIdString}` = `${source}:${target}`;
    const existing = this.rateLimitCountByPair.get(key);
    if (existing === undefined) {
      return false;
    }

    const newValue = existing + 1;
    debug(
      'isSendRateLimited: source=%j target=%j count=%d',
      source,
      target,
      newValue,
    );
    this.rateLimitCountByPair.set(key, newValue);
    return true;
  }

  //
  // Override `Server`'s methods to automatically pass keys to primary
  // devices.
  //
  // TODO(indutny): use popSingleUseKey() perhaps?
  //

  public override async updateDeviceKeys(
    device: Device,
    serviceIdKind: ServiceIdKind,
    keys: DeviceKeys,
  ): Promise<void> {
    await super.updateDeviceKeys(device, serviceIdKind, keys);

    const key = `${device.aci}.${device.getRegistrationId(serviceIdKind)}`;

    // Device is marked as provisioned only once we have its keys
    const resultQueue = this.provisionResultQueueByKey.get(key);
    if (!resultQueue) {
      return;
    }

    debug('updateDeviceKeys: got keys for', device.debugId, serviceIdKind);

    const { seenServiceIdKinds, promiseQueue } = resultQueue;

    assert(
      !seenServiceIdKinds.has(serviceIdKind),
      `Duplicate service id kind ${serviceIdKind} ` +
        `for device: ${device.debugId}`);
    seenServiceIdKinds.add(serviceIdKind);
    if (
      !seenServiceIdKinds.has(ServiceIdKind.ACI) ||
      !seenServiceIdKinds.has(ServiceIdKind.PNI)
    ) {
      return;
    }

    this.provisionResultQueueByKey.delete(key);
    await promiseQueue.pushAndWait(device);
  }

  public override async provisionDevice(
    options: ProvisionDeviceOptions,
  ): Promise<Device> {
    const { provisioningCode } = options;

    const queue = this.provisionResultQueueByCode.get(provisioningCode);
    assert(
      queue !== undefined,
      `Missing provision result queue for code: ${provisioningCode}`);
    this.provisionResultQueueByCode.delete(provisioningCode);

    const device = await super.provisionDevice(options);

    for (const serviceIdKind of [ ServiceIdKind.ACI, ServiceIdKind.PNI ]) {
      const key = `${device.aci}.${device.getRegistrationId(serviceIdKind)}`;
      this.provisionResultQueueByKey.set(key, queue);
    }

    const primary = this.primaryDevices.get(device.aci);
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
  ): Promise<ModifyGroupResult> {
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

    let queue = this.manifestQueueByAci.get(device.aci);
    if (!queue) {
      queue = this.createQueue();
      this.manifestQueueByAci.set(device.aci, queue);
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
