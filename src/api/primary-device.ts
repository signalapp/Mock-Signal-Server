// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import assert from 'assert';
import crypto from 'crypto';
import Long from 'long';
import {
  CiphertextMessageType,
  IdentityKeyStore,
  PreKeyBundle,
  PreKeyRecord,
  PreKeySignalMessage,
  PreKeyStore as PreKeyStoreBase,
  PrivateKey,
  ProtocolAddress,
  PublicKey,
  SenderCertificate,
  SenderKeyDistributionMessage,
  SenderKeyRecord,
  SenderKeyStore as SenderKeyStoreBase,
  SessionRecord,
  SessionStore as SessionStoreBase,
  SignalMessage,
  SignedPreKeyRecord,
  SignedPreKeyStore as SignedPreKeyStoreBase,
  Uuid,
} from '@signalapp/libsignal-client';
import * as SignalClient from '@signalapp/libsignal-client';
import createDebug from 'debug';
import {
  ClientZkProfileOperations,
  GroupMasterKey,
  GroupSecretParams,
  ProfileKey,
  ProfileKeyCredentialRequest,
  ProfileKeyCredentialResponse,
  ServerPublicParams,
} from '@signalapp/libsignal-client/zkgroup';

import { signalservice as Proto } from '../../protos/compiled';
import { INITIAL_PREKEY_COUNT } from '../constants';
import { DeviceId, UUID } from '../types';
import { Contact } from '../data/contacts';
import {
  decryptStorageItem,
  decryptStorageManifest,
  deriveAccessKey,
  encryptProfileName,
} from '../crypto';
import { EnvelopeType, StorageWriteResult } from '../server/base';
import { ServerGroup } from '../server/group';
import { Device, DeviceKeys, SingleUseKey } from '../data/device';
import { PromiseQueue, addressToString } from '../util';
import { Group } from './group';
import { StorageState } from './storage-state';

const debug = createDebug('mock:primary-device');

export type Config = Readonly<{
  profileName: string;
  contacts: Proto.IAttachmentPointer;
  groups: Proto.IAttachmentPointer;
  trustRoot: PublicKey;
  serverPublicParams: ServerPublicParams;

  // Server callbacks
  send(device: Device, message: Buffer): Promise<void>;
  getSenderCertificate(): Promise<SenderCertificate>;
  getDeviceByUUID(
    uuid: UUID,
    deviceId?: DeviceId,
  ): Promise<Device | undefined>;
  issueProfileKeyCredential(
    device: Device,
    request: ProfileKeyCredentialRequest,
  ): Promise<ProfileKeyCredentialResponse | undefined>;

  getGroup(publicParams: Buffer): Promise<ServerGroup | undefined>;
  createGroup(group: Proto.IGroup): Promise<ServerGroup>;

  getStorageManifest(): Promise<Proto.IStorageManifest | undefined>;
  getStorageItem(key: Buffer): Promise<Buffer | undefined>;
  waitForStorageManifest(afterVersion?: number): Promise<void>;
  applyStorageWrite(
    operation: Proto.IWriteOperation,
    shouldNotify?: boolean,
  ): Promise<StorageWriteResult>;
}>;

export type EncryptOptions = Readonly<{
  timestamp?: number;
  sealed?: boolean;
}>;

export type EncryptTextOptions = EncryptOptions & Readonly<{
  group?: Group;
  withProfileKey?: boolean;
}>;

export type CreateGroupOptions = Readonly<{
  title: string;
  members: ReadonlyArray<PrimaryDevice>;
}>;

export type SyncSentOptions = Readonly<{
  timestamp: number;
  destinationUUID: UUID;
}>;

export type FetchStorageOptions = Readonly<{
  timestamp: number;
}>;

export type SyncReadMessage = Readonly<{
  senderUUID: UUID;
  timestamp: number;
}>;

export type SyncReadOptions = Readonly<{
  timestamp?: number;
  messages: ReadonlyArray<SyncReadMessage>;
}>;

export enum ReceiptType {
  Delivery = 'Delivery',
  Read = 'Read',
}

export type ReceiptOptions = Readonly<{
  timestamp?: number;

  type: ReceiptType;
  messageTimestamps: ReadonlyArray<number>;
}>;

export type MessageQueueEntry = Readonly<{
  source: Device;
  envelopeType: EnvelopeType;
  body: string;
  dataMessage: Proto.IDataMessage;
}>;

enum SyncState {
  Empty = 0,
  Contacts = 1 << 0,
  Groups = 1 << 1,
  Blocked = 1 << 2,
  Configuration = 1 << 3,
  Keys = 1 << 4,

  Complete = Contacts | Groups | Blocked | Configuration | Keys,
}

type SyncEntry = {
  state: SyncState;
  onComplete: Promise<void>;
  complete(): void;
};

type DecryptResult = Readonly<{
  unsealedSource: Device;
  content: Proto.IContent;
  envelopeType: EnvelopeType;
}>;

class SignedPreKeyStore extends SignedPreKeyStoreBase {
  private readonly records = new Map<number, SignedPreKeyRecord>();

  async saveSignedPreKey(
    id: number,
    record: SignedPreKeyRecord,
  ): Promise<void> {
    this.records.set(id, record);
  }

  async getSignedPreKey(id: number): Promise<SignedPreKeyRecord> {
    const result = this.records.get(id);
    if (!result) {
      throw new Error(`Signed pre key not found: ${id}`);
    }
    return result;
  }
}

class PreKeyStore extends PreKeyStoreBase {
  private readonly records = new Map<number, PreKeyRecord>();

  async savePreKey(id: number, record: PreKeyRecord): Promise<void> {
    this.records.set(id, record);
  }

  async getPreKey(id: number): Promise<PreKeyRecord> {
    const record = this.records.get(id);
    if (!record) {
      throw new Error(`Pre key not found: ${id}`);
    }
    return record;
  }

  async removePreKey(id: number): Promise<void> {
    this.records.delete(id);
  }
}

class IdentityStore extends IdentityKeyStore {
  private knownIdentities = new Map<string, PublicKey>();

  constructor(
    private readonly privateKey: PrivateKey,
    private readonly registrationId: number,
  ) {
    super();

    this.privateKey = privateKey;
    this.registrationId = registrationId;
  }

  async getIdentityKey(): Promise<PrivateKey> {
    return this.privateKey;
  }

  async getLocalRegistrationId(): Promise<number> {
    if (this.registrationId === undefined) {
      throw new Error('Registration id not yet set');
    }

    return this.registrationId;
  }

  async saveIdentity(
    name: ProtocolAddress,
    key: PublicKey,
  ): Promise<boolean> {
    this.knownIdentities.set(addressToString(name), key);
    return true;
  }

  async isTrustedIdentity(): Promise<boolean> {
    // We trust everyone
    return true;
  }

  async getIdentity(name: ProtocolAddress): Promise<PublicKey | null> {
    return this.knownIdentities.get(addressToString(name)) ||
      null;
  }
}

export class SessionStore extends SessionStoreBase {
  private readonly sessions: Map<string, SessionRecord> = new Map();

  async saveSession(
    name: ProtocolAddress,
    record: SessionRecord,
  ): Promise<void> {
    this.sessions.set(addressToString(name), record);
  }

  async getSession(name: ProtocolAddress): Promise<SessionRecord | null> {
    return this.sessions.get(addressToString(name)) || null;
  }

  async getExistingSessions(
    addresses: ProtocolAddress[],
  ): Promise<SessionRecord[]> {
    return addresses.map((name) => {
      const existing = this.sessions.get(addressToString(name));
      if (!existing) {
        throw new Error('Existing session not found');
      }
      return existing;
    });
  }
}

export class SenderKeyStore extends SenderKeyStoreBase {
  private readonly keys: Map<string, SenderKeyRecord> = new Map();

  async saveSenderKey(
    sender: ProtocolAddress,
    distributionId: Uuid,
    record: SenderKeyRecord,
  ): Promise<void> {
    this.keys.set(`${addressToString(sender)}.${distributionId}`, record);
  }
  async getSenderKey(
    sender: ProtocolAddress,
    distributionId: Uuid,
  ): Promise<SenderKeyRecord | null> {
    const key = this.keys.get(`${addressToString(sender)}.${distributionId}`);
    return key || null;
  }
}

export class PrimaryDevice {
  private isInitialized = false;
  private lockPromise: Promise<void> | undefined;

  private readonly syncStates = new WeakMap<Device, SyncEntry>();
  private readonly storageKey = crypto.randomBytes(16);
  private readonly privateKey = PrivateKey.generate();
  private readonly contactsBlob: Proto.IAttachmentPointer;
  private readonly groupsBlob: Proto.IAttachmentPointer;
  private privSenderCertificate: SenderCertificate | undefined;
  private readonly messageQueue = new PromiseQueue<MessageQueueEntry>();

  // Various stores
  private readonly signedPreKeys = new SignedPreKeyStore();
  private readonly preKeys = new PreKeyStore();
  private readonly sessions = new SessionStore();
  private readonly senderKeys = new SenderKeyStore();
  private readonly identity: IdentityStore;

  public readonly signedPreKeyId: number = 1;
  public readonly publicKey = this.privateKey.getPublicKey();
  public readonly profileKey: ProfileKey;
  public readonly profileName: string;
  public readonly secondaryDevices = new Array<Device>();

  // TODO(indutny): make primary device type configurable
  public readonly userAgent = 'OWI';

  constructor(
    public readonly device: Device,
    private readonly config: Config,
  ) {
    this.identity = new IdentityStore(
      this.privateKey, this.device.registrationId);

    this.contactsBlob = this.config.contacts;
    this.groupsBlob = this.config.groups;
    this.profileName = config.profileName;

    this.profileKey = new ProfileKey(crypto.randomBytes(32));

    this.device.profileName = encryptProfileName(
      this.profileKey.serialize(),
      this.profileName,
    );
  }

  public async init(preKeyCount?: number): Promise<void> {
    if (this.isInitialized) {
      throw new Error('Already initialized');
    }

    await this.identity.saveIdentity(this.device.address, this.publicKey);

    await this.device.setKeys(await this.generateKeys(this.device, preKeyCount));

    this.privSenderCertificate = await this.config.getSenderCertificate();

    this.device.profileKeyCommitment = this.profileKey.getCommitment(
      this.device.uuid,
    );
    this.device.accessKey = deriveAccessKey(this.profileKey.serialize());

    this.isInitialized = true;
  }

  public toContact(): Contact {
    return {
      uuid: this.device.uuid,
      number: this.device.number,
      profileName: this.profileName,
      profileKey: this.profileKey.serialize(),
    };
  }

  public addSecondaryDevice(device: Device): void {
    this.secondaryDevices.push(device);

    device.profileName = this.device.profileName;
    device.profileKeyCommitment = this.device.profileKeyCommitment;
    device.accessKey = this.device.accessKey;
  }

  //
  // Keys
  //

  public async generateKeys(
    device: Device,
    preKeyCount = INITIAL_PREKEY_COUNT,
  ): Promise<DeviceKeys> {
    const signedPreKey = PrivateKey.generate();
    const signedPreKeySig = this.privateKey.sign(
      signedPreKey.getPublicKey().serialize());

    const shouldSave = device === this.device;

    const record = SignedPreKeyRecord.new(
      this.signedPreKeyId,
      Date.now(),
      signedPreKey.getPublicKey(),
      signedPreKey,
      signedPreKeySig);

    if (shouldSave) {
      await this.signedPreKeys.saveSignedPreKey(
        this.signedPreKeyId,
        record);
    }

    // NOTE: it is important to start with `1` here
    const preKeys: Array<{ keyId: number, publicKey: PublicKey }> = [];
    for (let i = 1; i <= preKeyCount; i++) {
      const preKey = PrivateKey.generate();
      const publicKey = preKey.getPublicKey();

      const record = PreKeyRecord.new(i, publicKey, preKey);
      if (shouldSave) {
        await this.preKeys.savePreKey(i, record);
      }

      preKeys.push({ keyId: i, publicKey });
    }

    return {
      identityKey: this.publicKey,
      signedPreKey: {
        keyId: this.signedPreKeyId,
        publicKey: signedPreKey.getPublicKey(),
        signature: signedPreKeySig,
      },
      preKeys,
    };
  }

  public async getIdentityKey(): Promise<PrivateKey> {
    return await this.identity.getIdentityKey();
  }

  public async addSingleUseKey(
    target: Device,
    key: SingleUseKey,
  ): Promise<void> {
    assert.ok(this.isInitialized, 'Not initialized');
    debug('adding singleUseKey for', target.debugId);

    await this.identity.saveIdentity(target.address, key.identityKey);

    const bundle = PreKeyBundle.new(
      target.registrationId,
      target.deviceId,
      key.preKey === undefined ? null : key.preKey.keyId,
      key.preKey === undefined ? null : key.preKey.publicKey,
      key.signedPreKey.keyId,
      key.signedPreKey.publicKey,
      key.signedPreKey.signature,
      key.identityKey,
    );
    await SignalClient.processPreKeyBundle(
      bundle,
      target.address,
      this.sessions,
      this.identity);
  }

  //
  // Groups
  //

  public async getAllGroups(
    storage: StorageState,
  ): Promise<ReadonlyArray<Group>> {
    const records = storage.getAllGroupRecords();

    return await Promise.all(
      records.map(async ({ record }) => {
        const { groupV2 } = record;
        assert.ok(groupV2, 'Not a group v2 record!');

        const { masterKey } = groupV2;
        assert.ok(masterKey, 'Group v2 record without master key');

        const secretParams = GroupSecretParams.deriveFromMasterKey(
          new GroupMasterKey(Buffer.from(masterKey)),
        );
        const publicParams = secretParams.getPublicParams().serialize();

        const serverGroup = await this.config.getGroup(publicParams);
        assert.ok(
          serverGroup,
          `Group not found: ${publicParams.toString('base64')}`,
        );

        return new Group(secretParams, serverGroup.state);
      }),
    );
  }

  public async createGroup(
    { title, members: memberDevices }: CreateGroupOptions,
  ): Promise<Group> {
    const ops = new ClientZkProfileOperations(
      this.config.serverPublicParams,
    );

    const groupParams = GroupSecretParams.generate();

    const members = await Promise.all(memberDevices.map(async (member) => {
      const { device, profileKey } = member;
      const ctx = ops.createProfileKeyCredentialRequestContext(
        device.uuid,
        profileKey,
      );
      const response = await this.config.issueProfileKeyCredential(
        member.device,
        ctx.getRequest(),
      );
      assert.ok(
        response,
        `Member device ${device.uuid} not initialized`,
      );

      const credential = ops.receiveProfileKeyCredential(ctx, response);

      const presentation = ops.createProfileKeyCredentialPresentation(
        groupParams,
        credential,
      );

      return {
        uuid: device.uuid,
        profileKey,
        presentation,
        joinedAtVersion: Long.fromNumber(0),
      };
    }));

    const clientGroup = Group.fromConfig({
      secretParams: groupParams,

      title,
      members,
    });

    await this.config.createGroup(clientGroup.state);

    return clientGroup;
  }

  //
  // Storage Service
  //

  public async waitForStorageState({ after }: {
    after?: StorageState,
  } = {}): Promise<StorageState> {
    debug('waiting for storage manifest', this.device.debugId);
    await this.config.waitForStorageManifest(after?.version);

    debug('got storage manifest', this.device.debugId);

    const state = await this.getStorageState();
    assert(state, 'Missing storage state');

    return state;
  }

  public async getStorageState(): Promise<StorageState | undefined> {
    const manifest = await this.config.getStorageManifest();
    if (!manifest) {
      return undefined;
    }

    return this.convertManifestToStorageState(manifest);
  }

  public async expectStorageState(reason: string): Promise<StorageState> {
    const state = await this.getStorageState();
    if (!state) {
      throw new Error(`expectStorageState: no storage state, ${reason}`);
    }

    return state;
  }

  public async setStorageState(state: StorageState): Promise<StorageState> {
    const writeOperation = state.createWriteOperation(this.storageKey);
    assert(writeOperation.manifest, 'write operation without manifest');

    const { updated, error } = await this.config.applyStorageWrite(
      writeOperation,
      false,
    );
    if (!updated) {
      throw new Error(`setStorageState: failed to update, ${error}`);
    }

    return this.convertManifestToStorageState(writeOperation.manifest);
  }

  //
  // Sync
  //

  // TODO(indutny): timeout
  public async waitForSync(secondaryDevice: Device): Promise<void> {
    debug('waiting for sync with %s', secondaryDevice.debugId);
    const { onComplete } = this.getSyncState(secondaryDevice);

    await onComplete;
  }

  public resetSyncState(secondaryDevice: Device): void {
    this.syncStates.delete(secondaryDevice);
  }

  //
  // Receive/Send
  //

  public async handleEnvelope(
    source: Device | undefined,
    envelopeType: EnvelopeType,
    encrypted: Buffer,
  ): Promise<void> {
    const { unsealedSource, content, envelopeType: unsealedType } =
      await this.lock(async () => {
        return await this.decrypt(source, envelopeType, encrypted);
      });

    let handled = true;
    if (content.syncMessage) {
      await this.handleSync(unsealedSource, content.syncMessage);
    } else if (content.dataMessage) {
      await this.handleDataMessage(
        unsealedSource,
        unsealedType,
        content.dataMessage,
      );
    } else {
      handled = false;
    }

    const { senderKeyDistributionMessage } = content;
    if (senderKeyDistributionMessage &&
        senderKeyDistributionMessage.length > 0) {
      handled = true;
      await this.processSenderKeyDistribution(
        unsealedSource,
        senderKeyDistributionMessage,
      );
    }


    if (!handled) {
      debug('unsupported message', content);
    }
  }

  public async encryptText(
    target: Device,
    text: string,
    options: EncryptTextOptions = {},
  ): Promise<Buffer> {
    const encryptOptions = {
      timestamp: Date.now(),
      ...options,
    };
    const content = {
      dataMessage: {
        groupV2: options.group?.toContext(),
        body: text,
        profileKey: options.withProfileKey ?
          this.profileKey.serialize() :
          undefined,
        timestamp: Long.fromNumber(encryptOptions.timestamp),
      },
    };
    return await this.encryptContent(target, content, encryptOptions);
  }

  public async encryptSyncSent(
    target: Device,
    text: string,
    options: SyncSentOptions,
  ): Promise<Buffer> {
    const dataMessage = {
      body: text,
      timestamp: Long.fromNumber(options.timestamp),
    };

    const content = {
      syncMessage: {
        sent: {
          destinationUuid: options.destinationUUID,
          timestamp: Long.fromNumber(options.timestamp),
          message: dataMessage,
        },
      },
    };
    return await this.encryptContent(target, content, options);
  }

  public async encryptSyncRead(
    target: Device,
    options: SyncReadOptions,
  ): Promise<Buffer> {
    const content = {
      syncMessage: {
        read: options.messages.map(({ senderUUID, timestamp }) => {
          return {
            senderUuid: senderUUID,
            timestamp: Long.fromNumber(timestamp),
          };
        }),
      },
    };
    return await this.encryptContent(target, content, options);
  }

  public async sendFetchStorage(
    options: FetchStorageOptions,
  ): Promise<void> {
    const content = {
      syncMessage: {
        fetchLatest: {
          type: Proto.SyncMessage.FetchLatest.Type.STORAGE_MANIFEST,
        },
      },
    };

    debug(
      'sending fetch storage to %d linked devices',
      this.secondaryDevices.length,
    );

    await Promise.all(
      this.secondaryDevices.map(async (device) => {
        const envelope = await this.encryptContent(device, content, options);

        await this.config.send(device, envelope);
      }),
    );
  }

  public async encryptReceipt(
    target: Device,
    options: ReceiptOptions,
  ): Promise<Buffer> {
    let type: Proto.ReceiptMessage.Type;
    if (options.type === ReceiptType.Delivery) {
      type = Proto.ReceiptMessage.Type.DELIVERY;
    } else {
      assert.strictEqual(options.type, ReceiptType.Read);
      type = Proto.ReceiptMessage.Type.READ;
    }

    const content = {
      receiptMessage: {
        type,
        timestamp: options.messageTimestamps.map(
          (timestamp) => Long.fromNumber(timestamp),
        ),
      },
    };
    return await this.encryptContent(target, content, options);
  }

  public async sendText(
    target: Device,
    text: string,
    options?: EncryptTextOptions,
  ): Promise<void> {
    await this.config.send(
      target,
      await this.encryptText(target, text, options));
  }

  public async receive(source: Device, encrypted: Buffer): Promise<void> {
    const envelope = Proto.Envelope.decode(encrypted);

    if (source.uuid !== envelope.sourceUuid) {
      throw new Error(`Invalid envelope source. Expected: ${source.uuid}, ` +
        `Got: ${envelope.sourceUuid}`);
    }

    let envelopeType: EnvelopeType;
    if (envelope.type === Proto.Envelope.Type.CIPHERTEXT) {
      envelopeType = EnvelopeType.CipherText;
    } else if (envelope.type === Proto.Envelope.Type.PREKEY_BUNDLE) {
      envelopeType = EnvelopeType.PreKey;
    } else if (envelope.type === Proto.Envelope.Type.UNIDENTIFIED_SENDER) {
      envelopeType = EnvelopeType.SealedSender;
    } else {
      throw new Error('Unsupported envelope type');
    }

    return await this.handleEnvelope(
      source, envelopeType, Buffer.from(envelope.content));
  }

  public async waitForMessage(): Promise<MessageQueueEntry> {
    return this.messageQueue.shift();
  }

  //
  // Private
  //

  private async encryptContent(
    target: Device,
    content: Proto.IContent,
    options?: EncryptOptions,
  ): Promise<Buffer> {
    const encoded = Buffer.from(Proto.Content.encode(content).finish());

    return await this.lock(async () => {
      return await this.encrypt(target, encoded, options);
    });
  }

  private getSyncState(secondaryDevice: Device): SyncEntry {
    const existing = this.syncStates.get(secondaryDevice);
    if (existing) {
      return existing;
    }

    let complete: (() => void) | undefined;
    const onComplete = new Promise<void>((resolve) => {
      complete = resolve;
    });

    if (!complete) {
      throw new Error('Failed to obtain resolve callback');
    }

    const entry = {
      state: SyncState.Empty,
      onComplete,
      complete,
    };
    this.syncStates.set(secondaryDevice, entry);

    return entry;
  }

  private async handleSync(
    source: Device,
    sync: Proto.ISyncMessage,
  ): Promise<void> {
    const { request } = sync;
    if (!request) {
      debug('ignoring sync responses');
      return;
    }

    let stateChange: SyncState;
    let response: Proto.ISyncMessage;
    if (request.type === Proto.SyncMessage.Request.Type.CONTACTS) {
      debug('got sync contacts request');
      response = {
        contacts: {
          blob: this.contactsBlob,
          complete: true,
        },
      };
      stateChange = SyncState.Contacts;
    } else if (request.type === Proto.SyncMessage.Request.Type.GROUPS) {
      debug('got sync groups request');
      response = {
        groups: {
          blob: this.groupsBlob,
        },
      };
      stateChange = SyncState.Groups;
    } else if (request.type === Proto.SyncMessage.Request.Type.BLOCKED) {
      debug('got sync blocked request');
      response = {
        blocked: {},
      };
      stateChange = SyncState.Blocked;
    } else if (request.type === Proto.SyncMessage.Request.Type.CONFIGURATION) {
      debug('got sync configuration request');
      response = {
        configuration: {
          readReceipts: true,
          unidentifiedDeliveryIndicators: false,
          typingIndicators: false,
          linkPreviews: false,
        },
      };
      stateChange = SyncState.Configuration;
    } else if (request.type === Proto.SyncMessage.Request.Type.KEYS) {
      debug('got sync keys request');
      response = {
        keys: { storageService: this.storageKey },
      };
      stateChange = SyncState.Keys;
    } else {
      debug('Unsupported sync request', request);
      return;
    }

    const encrypted = await this.encryptContent(source, {
      syncMessage: response,
    });
    await this.config.send(source, encrypted);

    const syncEntry = this.getSyncState(source);
    syncEntry.state |= stateChange;

    if (syncEntry.state === SyncState.Complete) {
      debug('sync with %s complete', source.debugId);
      syncEntry.complete();
    }
  }

  private async handleDataMessage(
    source: Device,
    envelopeType: EnvelopeType,
    dataMessage: Proto.IDataMessage,
  ): Promise<void> {
    const { body } = dataMessage;
    this.messageQueue.push({
      source,
      body: body ?? '',
      envelopeType,
      dataMessage,
    });
  }

  private async encrypt(
    target: Device,
    message: Buffer,
    { timestamp = Date.now(), sealed = false }: EncryptOptions = {},
  ): Promise<Buffer> {
    assert.ok(this.isInitialized, 'Not initialized');

    // "Pad"
    const paddedMessage = Buffer.concat([
      message,
      Buffer.from([ 0x80 ]),
    ]);

    let envelopeType: Proto.Envelope.Type;
    let content: Buffer;

    if (sealed) {
      content = await SignalClient.sealedSenderEncryptMessage(
        paddedMessage,
        target.address,
        this.senderCertificate,
        this.sessions,
        this.identity);

      envelopeType = Proto.Envelope.Type.UNIDENTIFIED_SENDER;
    } else {
      const ciphertext = await SignalClient.signalEncrypt(
        paddedMessage,
        target.address,
        this.sessions,
        this.identity);
      content = ciphertext.serialize();

      if (ciphertext.type() === CiphertextMessageType.Whisper) {
        envelopeType = Proto.Envelope.Type.CIPHERTEXT;
        debug('encrypting ciphertext envelope');
      } else {
        assert.strictEqual(ciphertext.type(), CiphertextMessageType.PreKey);
        envelopeType = Proto.Envelope.Type.PREKEY_BUNDLE;
        debug('encrypting prekeyBundle envelope');
      }
    }

    const envelope = Buffer.from(Proto.Envelope.encode({
      type: envelopeType,
      sourceUuid: this.device.uuid,
      sourceDevice: this.device.deviceId,
      serverTimestamp: Long.fromNumber(timestamp),
      destinationUuid: target.uuid,
      timestamp: Long.fromNumber(timestamp),
      content,
    }).finish());

    debug('encrypting envelope finish');

    return envelope;
  }

  private async decrypt(
    source: Device | undefined,
    envelopeType: EnvelopeType,
    encrypted: Buffer,
  ): Promise<DecryptResult> {
    debug('decrypting envelope type=%s start', envelopeType);

    let decrypted: Buffer;
    if (envelopeType === EnvelopeType.CipherText) {
      assert(source !== undefined, 'CipherText must have source');

      decrypted = await SignalClient.signalDecrypt(
        SignalMessage.deserialize(encrypted),
        source.address,
        this.sessions,
        this.identity);
    } else if (envelopeType === EnvelopeType.PreKey) {
      assert(source !== undefined, 'PreKey must have source');

      decrypted = await SignalClient.signalDecryptPreKey(
        PreKeySignalMessage.deserialize(encrypted),
        source.address,
        this.sessions,
        this.identity,
        this.preKeys,
        this.signedPreKeys);
    } else if (envelopeType === EnvelopeType.SenderKey) {
      assert(source !== undefined, 'SenderKey must have source');

      decrypted = await SignalClient.groupDecrypt(
        source.address,
        this.senderKeys,
        encrypted,
      );
    } else if (envelopeType === EnvelopeType.SealedSender) {
      assert(source === undefined, 'Sealed sender must have no source');

      const usmc =
        await SignalClient.sealedSenderDecryptToUsmc(encrypted, this.identity);

      const unsealedType = usmc.msgType();
      const certificate = usmc.senderCertificate();

      const sender = await this.config.getDeviceByUUID(
        certificate.senderUuid(),
        certificate.senderDeviceId());
      assert(sender !== undefined, 'Unsealed sender not found');

      let subType: EnvelopeType;
      switch (unsealedType) {
      case CiphertextMessageType.PreKey:
        subType = EnvelopeType.PreKey;
        break;
      case CiphertextMessageType.Whisper:
        subType = EnvelopeType.CipherText;
        break;
      case CiphertextMessageType.SenderKey:
        subType = EnvelopeType.SenderKey;
        break;
      default:
        throw new Error(`Unsupported usmc type: ${unsealedType}`);
      }

      // TODO(indutny): use sealedSenderDecryptMessage once it will support
      // sender key.
      return this.decrypt(
        sender,
        subType,
        usmc.contents(),
      );
    } else {
      throw new Error(`Unsupported envelope type: ${envelopeType}`);
    }

    // Remove padding
    let padding = 1;
    while (decrypted[decrypted.length - padding] !== 0x80) {
      assert.strictEqual(decrypted[decrypted.length - padding], 0);
      padding++;
    }

    const content = Proto.Content.decode(decrypted.slice(0, -padding));
    debug('decrypting envelope type=%s finish', envelopeType);
    return { unsealedSource: source, content, envelopeType };
  }

  private async lock<T>(callback: () => Promise<T>): Promise<T> {
    while (this.lockPromise) {
      await this.lockPromise;
    }

    let unlock: (() => void) | undefined;
    this.lockPromise = new Promise((resolve) => {
      unlock = resolve;
    });

    try {
      return await callback();
    } finally {
      this.lockPromise = undefined;
      assert.ok(unlock);
      unlock();
    }
  }

  private get senderCertificate(): SenderCertificate {
    if (!this.privSenderCertificate) {
      throw new Error('Sender certificate not set');
    }
    return this.privSenderCertificate;
  }

  private async processSenderKeyDistribution(
    source: Device,
    rawMessage: Uint8Array,
  ): Promise<void> {
    const message = SenderKeyDistributionMessage.deserialize(
      Buffer.from(rawMessage),
    );

    debug('received SKDM from', source.debugId);
    await SignalClient.processSenderKeyDistributionMessage(
      source.address,
      message,
      this.senderKeys,
    );
  }

  private async convertManifestToStorageState(
    manifest: Proto.IStorageManifest,
  ): Promise<StorageState> {
    const decryptedManifest = decryptStorageManifest(this.storageKey, manifest);
    assert(decryptedManifest.version, 'Consistency check');

    const version = decryptedManifest.version.toNumber();
    const items = await Promise.all((decryptedManifest.keys || []).map(
      async ({ type, raw: key }) => {
        assert(
          type !== null && type !== undefined,
          'Missing manifestRecord.keys.type',
        );
        assert(key, 'Missing manifestRecord.keys.raw');

        const keyBuffer = Buffer.from(key);
        const item = await this.config.getStorageItem(keyBuffer);
        if (!item) {
          throw new Error(`Missing item ${keyBuffer.toString('base64')}`);
        }

        return {
          type,
          key: keyBuffer,
          record: decryptStorageItem(this.storageKey, {
            key,
            value: item,
          }),
        };
      },
    ));

    return new StorageState(version, items);
  }
}
