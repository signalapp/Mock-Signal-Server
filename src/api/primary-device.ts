// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import assert from 'assert';
import crypto from 'crypto';
import Long from 'long';
import {
  CiphertextMessageType,
  IdentityKeyPair,
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
  ExpiringProfileKeyCredentialResponse,
  GroupMasterKey,
  GroupSecretParams,
  ProfileKey,
  ProfileKeyCredentialPresentation,
  ProfileKeyCredentialRequest,
  ServerPublicParams,
} from '@signalapp/libsignal-client/zkgroup';
import { parse as parseUUID } from 'uuid';

import { signalservice as Proto } from '../../protos/compiled';
import { DeviceId, PreKey, UUID, UUIDKind } from '../types';
import { Contact } from '../data/contacts';
import { Group as GroupData } from '../data/group';
import {
  decryptStorageItem,
  decryptStorageManifest,
  deriveAccessKey,
  encryptProfileName,
} from '../crypto';
import {
  EnvelopeType,
  ModifyGroupOptions,
  ModifyGroupResult,
  StorageWriteResult,
} from '../server/base';
import { ServerGroup } from '../server/group';
import {
  ChangeNumberOptions,
  Device,
  DeviceKeys,
  SingleUseKey,
} from '../data/device';
import { PromiseQueue, addressToString, generateRegistrationId } from '../util';
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
  generateNumber(): Promise<string>;
  generateUUID(): Promise<UUID>;
  releaseUUID(uuid: UUID): Promise<void>;
  changeDeviceNumber(
    device: Device,
    options: ChangeNumberOptions,
  ): Promise<void>;
  send(device: Device, message: Buffer): Promise<void>;
  getSenderCertificate(): Promise<SenderCertificate>;
  getDeviceByUUID(
    uuid: UUID,
    deviceId?: DeviceId,
  ): Promise<Device | undefined>;
  issueExpiringProfileKeyCredential(
    device: Device,
    request: ProfileKeyCredentialRequest,
  ): Promise<Buffer | undefined>;

  getGroup(publicParams: Buffer): Promise<ServerGroup | undefined>;
  createGroup(group: Proto.IGroup): Promise<ServerGroup>;
  modifyGroup(options: ModifyGroupOptions): Promise<ModifyGroupResult>;
  waitForGroupUpdate(group: GroupData): Promise<void>;

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
  uuidKind?: UUIDKind;
  updatedPni?: UUID;
}>;

export type EncryptTextOptions = EncryptOptions & Readonly<{
  group?: Group;
  withProfileKey?: boolean;
  withPniSignature?: boolean;
}>;

export type CreateGroupOptions = Readonly<{
  title: string;
  members: ReadonlyArray<PrimaryDevice>;
}>;

export type InviteToGroupOptions = EncryptOptions & Readonly<{
  sendInvite?: boolean;
}>;

export type SyncSentOptions = Readonly<{
  timestamp: number;
  destinationUUID: UUID;
}>;

export type FetchStorageOptions = Readonly<{
  timestamp: number;
}>;

export type SendStickerPackSyncOptions = Readonly<{
  type: 'install' | 'remove';
  packId: Buffer;
  packKey: Buffer;
  timestamp?: number;
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

export type UnencryptedReceiptOptions = Readonly<{
  timestamp?: number;
  messageTimestamp: number;
}>;

export type MessageQueueEntry = Readonly<{
  source: Device;
  uuidKind: UUIDKind;
  envelopeType: EnvelopeType;
  body: string;
  dataMessage: Proto.IDataMessage;
  content: Proto.IContent;
}>;

export type ReceiptQueueEntry = Readonly<{
  source: Device;
  uuidKind: UUIDKind;
  envelopeType: EnvelopeType;
  receiptMessage: Proto.IReceiptMessage;
  content: Proto.IContent;
}>;

export type StoryQueueEntry = Readonly<{
  source: Device;
  uuidKind: UUIDKind;
  envelopeType: EnvelopeType;
  storyMessage: Proto.IStoryMessage;
  content: Proto.IContent;
}>;

export type SyncMessageQueueEntry = Readonly<{
  source: Device;
  syncMessage: Proto.ISyncMessage;
}>;

export type PrepareChangeNumberEntry = Readonly<{
  device: Device;
  envelope: Buffer;
}>;

export type PrepareChangeNumberResult = ReadonlyArray<PrepareChangeNumberEntry>;

export type ToContactOptions = Readonly<{
  includeProfileKey?: boolean;
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
  private lastId = 0;
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

  public getNextId(): number {
    this.lastId += 1;

    // Note: intentionally starting from 1
    return this.lastId;
  }
}

class IdentityStore extends IdentityKeyStore {
  private knownIdentities = new Map<string, PublicKey>();

  constructor(
    private privateKey: PrivateKey,
    private registrationId: number,
  ) {
    super();
  }

  async getIdentityKey(): Promise<PrivateKey> {
    return this.privateKey;
  }

  async getLocalRegistrationId(): Promise<number> {
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

  // Not part of IdentityKeyStore API

  async updateIdentityKey(privateKey: PrivateKey): Promise<void> {
    this.privateKey = privateKey;
  }

  async updateLocalRegistrationId(registrationId: number): Promise<void> {
    this.registrationId = registrationId;
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
  private pniPrivateKey = PrivateKey.generate();
  private readonly contactsBlob: Proto.IAttachmentPointer;
  private readonly groupsBlob: Proto.IAttachmentPointer;
  private privSenderCertificate: SenderCertificate | undefined;
  private readonly messageQueue = new PromiseQueue<MessageQueueEntry>();
  private readonly receiptQueue = new PromiseQueue<ReceiptQueueEntry>();
  private readonly storyQueue = new PromiseQueue<StoryQueueEntry>();
  private readonly syncMessageQueue = new PromiseQueue<SyncMessageQueueEntry>();
  private privPniPublicKey = this.pniPrivateKey.getPublicKey();

  // Various stores
  private readonly signedPreKeys = new Map<UUIDKind, SignedPreKeyStore>();
  private readonly preKeys = new Map<UUIDKind, PreKeyStore>();
  private readonly sessions = new SessionStore();
  private readonly senderKeys = new Map<UUIDKind, SenderKeyStore>();
  private readonly identity = new Map<UUIDKind, IdentityStore>();

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
    for (const uuidKind of [ UUIDKind.ACI, UUIDKind.PNI ]) {
      this.identity.set(uuidKind, new IdentityStore(
        uuidKind === UUIDKind.ACI ? this.privateKey : this.pniPrivateKey,
        this.device.getRegistrationId(uuidKind),
      ));

      this.preKeys.set(uuidKind, new PreKeyStore());
      this.signedPreKeys.set(uuidKind, new SignedPreKeyStore());
      this.senderKeys.set(uuidKind, new SenderKeyStore());
    }

    this.contactsBlob = this.config.contacts;
    this.groupsBlob = this.config.groups;
    this.profileName = config.profileName;

    this.profileKey = new ProfileKey(crypto.randomBytes(32));

    this.device.profileName = encryptProfileName(
      this.profileKey.serialize(),
      this.profileName,
    );
  }

  public async init(): Promise<void> {
    if (this.isInitialized) {
      throw new Error('Already initialized');
    }

    for (const uuidKind of [ UUIDKind.ACI, UUIDKind.PNI ]) {
      const identity = this.identity.get(uuidKind);
      assert.ok(identity);
      await identity.saveIdentity(
        this.device.getAddressByKind(uuidKind),
        this.getPublicKey(uuidKind),
      );
      await this.device.setKeys(
        uuidKind,
        await this.generateKeys(this.device, uuidKind),
      );
    }

    this.privSenderCertificate = await this.config.getSenderCertificate();

    this.device.profileKeyCommitment = this.profileKey.getCommitment(
      this.device.uuid,
    );
    this.device.accessKey = deriveAccessKey(this.profileKey.serialize());

    this.isInitialized = true;
  }

  public toContact({
    includeProfileKey = true,
  }: ToContactOptions = {}): Contact {
    return {
      uuid: this.device.uuid,
      number: this.device.number,
      profileName: this.profileName,
      profileKey: includeProfileKey ? this.profileKey.serialize() : undefined,
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
    uuidKind: UUIDKind,
  ): Promise<DeviceKeys & { signedPreKeyRecord: SignedPreKeyRecord }> {
    const signedPreKey = PrivateKey.generate();
    const signedPreKeySig = this.getPrivateKey(uuidKind).sign(
      signedPreKey.getPublicKey().serialize());

    const shouldSave = device === this.device;

    const signedPreKeyRecord = SignedPreKeyRecord.new(
      this.signedPreKeyId,
      Date.now(),
      signedPreKey.getPublicKey(),
      signedPreKey,
      signedPreKeySig);

    if (shouldSave) {
      await this.signedPreKeys.get(uuidKind)?.saveSignedPreKey(
        this.signedPreKeyId,
        signedPreKeyRecord);
    }

    return {
      identityKey: this.getPublicKey(uuidKind),
      signedPreKey: {
        keyId: this.signedPreKeyId,
        publicKey: signedPreKey.getPublicKey(),
        signature: signedPreKeySig,
      },
      preKeyIterator: this.getPreKeyIterator(device, uuidKind),

      signedPreKeyRecord: signedPreKeyRecord,
    };
  }

  private async *getPreKeyIterator(
    device: Device,
    uuidKind: UUIDKind,
  ): AsyncIterator<PreKey> {
    const preKeyStore = this.preKeys.get(uuidKind);
    assert.ok(preKeyStore, 'Missing preKey store');

    const shouldSave = device === this.device;

    while (true) {
      const preKey = PrivateKey.generate();
      const publicKey = preKey.getPublicKey();
      const keyId = preKeyStore.getNextId();

      if (shouldSave) {
        const record = PreKeyRecord.new(keyId, publicKey, preKey);
        await preKeyStore.savePreKey(keyId, record);
      }

      yield { keyId, publicKey };
    }
  }

  public async getIdentityKey(uuidKind: UUIDKind): Promise<PrivateKey> {
    const identity = this.identity.get(uuidKind);
    assert.ok(identity);
    return identity.getIdentityKey();
  }

  public getPublicKey(uuidKind: UUIDKind): PublicKey {
    switch (uuidKind) {
    case UUIDKind.ACI:
      return this.publicKey;
    case UUIDKind.PNI:
      return this.privPniPublicKey;
    }
  }

  public async addSingleUseKey(
    target: Device,
    key: SingleUseKey,
    uuidKind = UUIDKind.ACI,
  ): Promise<void> {
    assert.ok(this.isInitialized, 'Not initialized');
    debug('adding singleUseKey for', target.debugId);

    // Outgoing stores
    const identity = this.identity.get(UUIDKind.ACI);
    assert(identity, 'Should have an ACI identity');

    await identity.saveIdentity(
      target.getAddressByKind(uuidKind),
      key.identityKey,
    );

    const bundle = PreKeyBundle.new(
      target.getRegistrationId(uuidKind),
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
      target.getAddressByKind(uuidKind),
      this.sessions,
      identity);
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

        return new Group({
          secretParams,
          groupState: serverGroup.state,
        });
      }),
    );
  }

  public async createGroup(
    { title, members: memberDevices }: CreateGroupOptions,
  ): Promise<Group> {
    const groupParams = GroupSecretParams.generate();

    const members = await Promise.all(memberDevices.map(async (member) => {
      const presentation = await member.getProfileKeyPresentation(groupParams);

      return {
        uuid: member.device.uuid,
        profileKey: member.profileKey,
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

  public async waitForGroupUpdate(group: Group): Promise<Group> {
    await this.config.waitForGroupUpdate(group);

    const publicParams = group.publicParams.serialize();
    const serverGroup = await this.config.getGroup(publicParams);
    assert.ok(serverGroup, `Group not found: ${group.id}`);

    return new Group({
      secretParams: group.secretParams,
      groupState: serverGroup.state,
    });
  }

  public async inviteToGroup(
    group: Group,
    device: Device,
    options: InviteToGroupOptions = {},
  ): Promise<Group> {
    const { uuidKind = UUIDKind.ACI, sendInvite = true } = options;

    const serverGroup = await this.config.getGroup(
      group.publicParams.serialize(),
    );
    assert(serverGroup !== undefined, 'Group does not exist on server');

    const targetUUID = device.getUUIDByKind(uuidKind);
    const userId = group.encryptUUID(targetUUID);

    const modifyResult = await this.config.modifyGroup({
      group: serverGroup,
      actions: {
        version: group.revision + 1,
        addPendingMembers: [ {
          added: {
            member: { userId, role: Proto.Member.Role.DEFAULT },
          },
        } ],
      },
      aciCiphertext: group.encryptUUID(this.device.uuid),
      pniCiphertext: group.encryptUUID(this.device.pni),
    });

    assert(!modifyResult.conflict, 'Group update conflict!');

    const updatedGroup = new Group({
      secretParams: group.secretParams,
      groupState: serverGroup.state,
    });

    if (sendInvite) {
      // Send the invitation
      const encryptOptions = {
        timestamp: Date.now(),
        ...options,
      };
      const envelope = await this.encryptContent(device, {
        dataMessage: {
          groupV2: {
            ...updatedGroup.toContext(),
            groupChange: Proto.GroupChange.encode(
              modifyResult.signedChange,
            ).finish(),
          },
          timestamp: Long.fromNumber(encryptOptions.timestamp),
        },
      }, encryptOptions);
      await this.config.send(device, envelope);
    }

    return updatedGroup;
  }

  public async acceptPniInvite(
    group: Group,
    device: Device,
    options: EncryptOptions = {},
  ): Promise<Group> {
    const serverGroup = await this.config.getGroup(
      group.publicParams.serialize(),
    );
    assert(serverGroup !== undefined, 'Group does not exist on server');

    const aciCiphertext = group.encryptUUID(this.device.uuid);
    const pniCiphertext = group.encryptUUID(this.device.pni);

    const presentation =
      await this.getProfileKeyPresentation(group.secretParams);

    const modifyResult = await this.config.modifyGroup({
      group: serverGroup,
      actions: {
        version: group.revision + 1,
        promoteMembersPendingPniAciProfileKey: [ {
          presentation: presentation.serialize(),
        } ],
      },
      aciCiphertext,
      pniCiphertext,
    });

    assert(!modifyResult.conflict, 'Group update conflict!');

    const updatedGroup = new Group({
      secretParams: group.secretParams,
      groupState: serverGroup.state,
    });

    // Send the invitation
    const encryptOptions = {
      timestamp: Date.now(),
      ...options,
    };
    const envelope = await this.encryptContent(device, {
      dataMessage: {
        groupV2: {
          ...updatedGroup.toContext(),
          groupChange: Proto.GroupChange.encode(
            modifyResult.signedChange,
          ).finish(),
        },
        timestamp: Long.fromNumber(encryptOptions.timestamp),
      },
    }, encryptOptions);
    await this.config.send(device, envelope);

    return updatedGroup;
  }

  //
  // Storage Service
  //

  public async waitForStorageState({ after }: {
    after?: StorageState,
  } = {}): Promise<StorageState> {
    debug(
      'waiting for storage manifest for device=%s after version=%d',
      this.device.debugId,
      after?.version,
    );
    await this.config.waitForStorageManifest(after?.version);

    const state = await this.getStorageState();
    assert(state, 'Missing storage state');

    debug(
      'got storage manifest for device=%s version=%d',
      this.device.debugId,
      state.version,
    );

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
    uuidKind: UUIDKind,
    envelopeType: EnvelopeType,
    encrypted: Buffer,
  ): Promise<void> {
    const { unsealedSource, content, envelopeType: unsealedType } =
      await this.lock(async () => {
        return await this.decrypt(source, uuidKind, envelopeType, encrypted);
      });

    let handled = true;
    if (content.syncMessage) {
      assert.strictEqual(uuidKind, UUIDKind.ACI, 'Got sync message on PNI');
      await this.handleSync(unsealedSource, content.syncMessage);
    } else if (content.dataMessage) {
      this.handleDataMessage(
        unsealedSource,
        uuidKind,
        unsealedType,
        content,
      );
    } else if (content.storyMessage) {
      this.handleStoryMessage(
        unsealedSource,
        uuidKind,
        unsealedType,
        content,
      );
    } else if (content.receiptMessage) {
      this.handleReceiptMessage(
        unsealedSource,
        uuidKind,
        unsealedType,
        content,
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

    let pniSignatureMessage: Proto.IPniSignatureMessage | undefined;
    if (options.withPniSignature) {
      const pniPrivate = this.getPrivateKey(UUIDKind.PNI);
      const pniPublic = this.getPublicKey(UUIDKind.PNI);
      const aciPublic = this.getPublicKey(UUIDKind.ACI);

      const pniIdentity = new IdentityKeyPair(pniPublic, pniPrivate);

      const signature = pniIdentity.signAlternateIdentity(aciPublic);

      pniSignatureMessage = {
        pni: new Uint8Array(parseUUID(this.device.pni)),
        signature,
      };
    }

    const content: Proto.IContent = {
      dataMessage: {
        groupV2: options.group?.toContext(),
        body: text,
        profileKey: options.withProfileKey ?
          this.profileKey.serialize() :
          undefined,
        timestamp: Long.fromNumber(encryptOptions.timestamp),
      },
      pniSignatureMessage,
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

    return this.broadcast('fetch storage', content, options);
  }

  public async sendStickerPackSync(
    options: SendStickerPackSyncOptions,
  ): Promise<void> {
    const Type = Proto.SyncMessage.StickerPackOperation.Type;

    const content = {
      syncMessage: {
        stickerPackOperation: [ {
          packId: options.packId,
          packKey: options.packKey,
          type: options.type === 'install' ? Type.INSTALL : Type.REMOVE,
        } ],
      },
    };

    return this.broadcast('sticker pack sync', content, options);
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

  public async sendReceipt(
    target: Device,
    options: ReceiptOptions,
  ): Promise<void> {
    const receipt = await this.encryptReceipt(target, options);
    return this.config.send(target, receipt);
  }

  public async sendUnencryptedReceipt(
    target: Device,
    { messageTimestamp, timestamp = Date.now() }: UnencryptedReceiptOptions,
  ): Promise<void> {
    const envelope: Proto.IEnvelope = {
      type: Proto.Envelope.Type.RECEIPT,
      timestamp: Long.fromNumber(messageTimestamp),
      serverTimestamp: Long.fromNumber(timestamp),
      sourceUuid: this.device.uuid,
      sourceDevice: this.device.deviceId,
      destinationUuid: target.uuid,
    };
    return this.config.send(
      target,
      Buffer.from(Proto.Envelope.encode(envelope).finish()),
    );
  }

  public async prepareChangeNumber(
    options: EncryptOptions = {},
  ): Promise<PrepareChangeNumberResult> {
    const { timestamp = Date.now() } = options;

    const newNumber = await this.config.generateNumber();
    const newPni = await this.config.generateUUID();
    const newPniRegistrationId = generateRegistrationId();
    const newPniIdentity = IdentityKeyPair.generate();

    debug(
      'sending change number to %d linked devices timestamp=%d newPni=%s',
      this.secondaryDevices.length,
      timestamp,
      newPni,
    );

    this.pniPrivateKey = newPniIdentity.privateKey;
    this.privPniPublicKey = newPniIdentity.publicKey;

    const allDevices = [ this.device, ...this.secondaryDevices ];

    const oldPni = this.device.pni;

    // Update PNI
    await Promise.all(allDevices.map(async (device) => {
      await this.config.changeDeviceNumber(device, {
        pni: newPni,
        number: newNumber,
        pniRegistrationId: newPniRegistrationId,
      });
    }));

    const identity = this.identity.get(UUIDKind.PNI);
    assert(identity, 'Should have a PNI identity');
    await identity.updateIdentityKey(newPniIdentity.privateKey);
    await identity.updateLocalRegistrationId(newPniRegistrationId);
    await identity.saveIdentity(
      this.device.getAddressByKind(UUIDKind.PNI),
      this.getPublicKey(UUIDKind.PNI),
    );

    await this.config.releaseUUID(oldPni);

    // Update all keys and prepare sync message
    const results = await Promise.all(
      allDevices.map(async (device) => {
        const isPrimary = device === this.device;
        const keys = await this.generateKeys(device, UUIDKind.PNI);
        await device.setKeys(UUIDKind.PNI, keys);

        if (isPrimary) {
          return;
        }

        // Send sync message
        const { signedPreKeyRecord } = keys;

        const content = {
          syncMessage: {
            pniChangeNumber: {
              identityKeyPair: newPniIdentity.serialize(),
              signedPreKey: signedPreKeyRecord.serialize(),
              registrationId: newPniRegistrationId,
            },
          },
        };

        const envelope = await this.encryptContent(device, content, {
          ...options,
          timestamp,
          updatedPni: this.device.pni,
        });

        return { device, envelope };
      }),
    );

    return results.filter((entry): entry is PrepareChangeNumberEntry => {
      return entry !== undefined;
    });
  }

  public async sendChangeNumber(
    result: PrepareChangeNumberResult,
  ): Promise<void> {
    await Promise.all(result.map(({ device, envelope }) => {
      return this.config.send(device, envelope);
    }));
  }

  public async changeNumber(
    options: EncryptOptions = {},
  ): Promise<void> {
    const result = await this.prepareChangeNumber(options);
    await this.sendChangeNumber(result);
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

  public async sendRaw(
    target: Device,
    content: Proto.IContent,
    options?: EncryptOptions,
  ): Promise<void> {
    await this.config.send(
      target,
      await this.encryptContent(target, content, options));
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

    const uuidKind = envelope.destinationUuid ?
      this.device.getUUIDKind(envelope.destinationUuid) :
      UUIDKind.ACI;

    return await this.handleEnvelope(
      source, uuidKind, envelopeType, Buffer.from(envelope.content));
  }

  public async waitForMessage(): Promise<MessageQueueEntry> {
    return this.messageQueue.shift();
  }

  public async waitForReceipt(): Promise<ReceiptQueueEntry> {
    return this.receiptQueue.shift();
  }

  public async waitForStory(): Promise<StoryQueueEntry> {
    return this.storyQueue.shift();
  }

  public async waitForSyncMessage(
    predicate: ((entry: SyncMessageQueueEntry) => boolean) = () => true,
  ): Promise<SyncMessageQueueEntry> {
    for (;;) {
      const entry = await this.syncMessageQueue.shift();
      if (!predicate(entry)) {
        continue;
      }
      return entry;
    }
  }

  //
  // Private
  //

  private async getProfileKeyPresentation(
    groupParams: GroupSecretParams,
  ): Promise<ProfileKeyCredentialPresentation> {
    const ops = new ClientZkProfileOperations(
      this.config.serverPublicParams,
    );

    const ctx = ops.createProfileKeyCredentialRequestContext(
      this.device.uuid,
      this.profileKey,
    );
    const response = await this.config.issueExpiringProfileKeyCredential(
      this.device,
      ctx.getRequest(),
    );
    assert.ok(
      response,
      `Member device ${this.device.uuid} not initialized`,
    );

    const credential = ops.receiveExpiringProfileKeyCredential(
      ctx,
      new ExpiringProfileKeyCredentialResponse(response),
    );

    return ops.createExpiringProfileKeyCredentialPresentation(
      groupParams,
      credential,
    );
  }

  private getPrivateKey(uuidKind: UUIDKind): PrivateKey {
    switch (uuidKind) {
    case UUIDKind.ACI:
      return this.privateKey;
    case UUIDKind.PNI:
      return this.pniPrivateKey;
    }
  }

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

  private async broadcast(
    type: string,
    content: Proto.IContent,
    options?: EncryptOptions,
  ): Promise<void> {
    debug(
      'broadcasting %s to %d linked devices',
      type,
      this.secondaryDevices.length,
    );

    await Promise.all(
      this.secondaryDevices.map(async (device) => {
        const envelope = await this.encryptContent(device, content, options);

        await this.config.send(device, envelope);
      }),
    );
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
      debug('got generic sync message');
      this.syncMessageQueue.push({
        source,
        syncMessage: sync,
      });
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

    // Intentionally not awaiting since the device might be offline or
    // not responding.
    void this.config.send(source, encrypted);

    const syncEntry = this.getSyncState(source);
    syncEntry.state |= stateChange;

    if (syncEntry.state === SyncState.Complete) {
      debug('sync with %s complete', source.debugId);
      syncEntry.complete();
    }
  }

  private handleDataMessage(
    source: Device,
    uuidKind: UUIDKind,
    envelopeType: EnvelopeType,
    content: Proto.IContent,
  ): void {
    const { dataMessage } = content;
    assert.ok(dataMessage, 'dataMessage must be present');

    const { body } = dataMessage;
    this.messageQueue.push({
      source,
      uuidKind,
      body: body ?? '',
      envelopeType,
      dataMessage,
      content,
    });
  }

  private handleReceiptMessage(
    source: Device,
    uuidKind: UUIDKind,
    envelopeType: EnvelopeType,
    content: Proto.IContent,
  ): void {
    const { receiptMessage } = content;
    assert.ok(receiptMessage, 'receiptMessage must be present');

    this.receiptQueue.push({
      source,
      uuidKind,
      envelopeType,
      receiptMessage,
      content,
    });
  }

  private handleStoryMessage(
    source: Device,
    uuidKind: UUIDKind,
    envelopeType: EnvelopeType,
    content: Proto.IContent,
  ): void {
    const { storyMessage } = content;
    assert.ok(storyMessage, 'storyMessage must be present');

    this.storyQueue.push({
      source,
      uuidKind,
      envelopeType,
      storyMessage,
      content,
    });
  }

  private async encrypt(
    target: Device,
    message: Buffer,
    {
      timestamp = Date.now(),
      sealed = false,
      uuidKind = UUIDKind.ACI,
      updatedPni,
    }: EncryptOptions = {},
  ): Promise<Buffer> {
    assert.ok(this.isInitialized, 'Not initialized');

    // "Pad"
    const paddedMessage = Buffer.concat([
      message,
      Buffer.from([ 0x80 ]),
    ]);

    let envelopeType: Proto.Envelope.Type;
    let content: Buffer;

    // Outgoing stores
    const identity = this.identity.get(UUIDKind.ACI);
    assert(identity, 'Should have an ACI identity');

    if (sealed) {
      assert(uuidKind === UUIDKind.ACI, 'Can\'t send sealed sender to PNI');

      content = await SignalClient.sealedSenderEncryptMessage(
        paddedMessage,
        target.getAddressByKind(uuidKind),
        this.senderCertificate,
        this.sessions,
        identity);

      envelopeType = Proto.Envelope.Type.UNIDENTIFIED_SENDER;
    } else {
      const ciphertext = await SignalClient.signalEncrypt(
        paddedMessage,
        target.getAddressByKind(uuidKind),
        this.sessions,
        identity);
      content = ciphertext.serialize();

      if (ciphertext.type() === CiphertextMessageType.Whisper) {
        assert(
          uuidKind === UUIDKind.ACI,
          'Can\'t send non-prekey messages to PNI',
        );

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
      destinationUuid: target.getUUIDByKind(uuidKind),
      updatedPni,
      serverTimestamp: Long.fromNumber(timestamp),
      timestamp: Long.fromNumber(timestamp),
      content,
    }).finish());

    debug('encrypting envelope finish');

    return envelope;
  }

  private async decrypt(
    source: Device | undefined,
    uuidKind: UUIDKind,
    envelopeType: EnvelopeType,
    encrypted: Buffer,
  ): Promise<DecryptResult> {
    debug('decrypting envelope type=%s start', envelopeType);

    const identity = this.identity.get(uuidKind);
    const preKeys = this.preKeys.get(uuidKind);
    const signedPreKeys = this.signedPreKeys.get(uuidKind);
    const senderKeys = this.senderKeys.get(uuidKind);
    assert(
      identity && preKeys && signedPreKeys && senderKeys,
      'Should have identity, prekey/signed prekey/senderkey stores',
    );

    let decrypted: Buffer;
    if (envelopeType === EnvelopeType.CipherText) {
      assert(source !== undefined, 'CipherText must have source');

      decrypted = await SignalClient.signalDecrypt(
        SignalMessage.deserialize(encrypted),
        source.getAddressByKind(uuidKind),
        this.sessions,
        identity);
    } else if (envelopeType === EnvelopeType.PreKey) {
      assert(source !== undefined, 'PreKey must have source');

      decrypted = await SignalClient.signalDecryptPreKey(
        PreKeySignalMessage.deserialize(encrypted),
        source.getAddressByKind(uuidKind),
        this.sessions,
        identity,
        preKeys,
        signedPreKeys);
    } else if (envelopeType === EnvelopeType.SenderKey) {
      assert(source !== undefined, 'SenderKey must have source');

      decrypted = await SignalClient.groupDecrypt(
        source.getAddressByKind(uuidKind),
        senderKeys,
        encrypted,
      );
    } else if (envelopeType === EnvelopeType.SealedSender) {
      assert(source === undefined, 'Sealed sender must have no source');

      const usmc =
        await SignalClient.sealedSenderDecryptToUsmc(encrypted, identity);

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
      const result = await this.decrypt(
        sender,
        uuidKind,
        subType,
        usmc.contents(),
      );

      if (uuidKind === UUIDKind.PNI) {
        debug('sealed message on PNI', result);
        throw new Error('Got sealed message on PNI');
      }

      return result;
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

    const senderKeys = this.senderKeys.get(UUIDKind.ACI);
    assert(senderKeys, 'Should have a sender key store');

    debug('received SKDM from', source.debugId);
    await SignalClient.processSenderKeyDistributionMessage(
      source.address,
      message,
      senderKeys,
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
