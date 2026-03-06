// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import assert from 'assert';
import crypto from 'crypto';
import { Buffer } from 'node:buffer';

import { signalservice as Proto } from '../../protos/compiled';
import { encryptStorageItem, encryptStorageManifest } from '../crypto';
import { Device } from '../data/device';
import { ServiceIdKind } from '../types';
import { Group } from './group';
import { PrimaryDevice } from './primary-device';

type RecordValue = NonNullable<Proto.StorageRecord.Params['record']>;

export type StorageStateRecord<Value extends RecordValue = RecordValue> =
  Readonly<{
    type: Proto.ManifestRecord.Identifier.Type;
    key: Buffer;
    record: Value;
  }>;

export type StorageStateNewRecord = Readonly<{
  type: Proto.ManifestRecord.Identifier.Type;
  key?: Buffer;
  record: RecordValue;
}>;

export type DiffResult = Readonly<{
  added: ReadonlyArray<RecordValue>;
  removed: ReadonlyArray<RecordValue>;
}>;

const KEY_SIZE = 16;

const IdentifierType = Proto.ManifestRecord.Identifier.Type;
type IdentifierType = Proto.ManifestRecord.Identifier.Type;

export type ToStorageItemOptions = Readonly<{
  storageKey: Buffer;
  recordIkm: Buffer | undefined;
}>;

export type CreateWriteOperationOptions = Readonly<{
  storageKey: Buffer;
  recordIkm: Buffer | undefined;
  previous?: StorageState;
}>;

type StorageRecordPredicate<Value extends RecordValue> = (
  record: StorageStateRecord,
) => record is StorageStateRecord<Value>;
type StorageRecordMapper<Value extends RecordValue> = (record: Value) => Value;
type StorageItemPredicate<Value extends RecordValue> = (
  item: StorageStateItem,
  index: number,
) => item is StorageStateItem<Value>;

class StorageStateItem<Value extends RecordValue = RecordValue> {
  public readonly type: IdentifierType;
  public readonly key: Buffer;
  public readonly record: Value;

  constructor({ type, key, record }: StorageStateRecord<Value>) {
    this.type = type;
    this.key = key;
    this.record = record;
  }

  public getKeyString(): string {
    return this.key.toString('base64');
  }

  public toStorageItem({
    storageKey,
    recordIkm,
  }: ToStorageItemOptions): Proto.StorageItem.Params {
    return encryptStorageItem({
      storageKey,
      recordIkm,
      key: this.key,
      record: {
        record: this.record,
      },
    });
  }

  public toIdentifier(): Proto.ManifestRecord.Identifier.Params {
    return {
      type: this.type,
      raw: this.key,
    };
  }

  public isAccount(): this is StorageStateItem<
    Extract<RecordValue, { account: unknown }>
  > {
    return this.type === IdentifierType.ACCOUNT && this.record.account != null;
  }

  public isGroup(
    group: Group,
  ): this is StorageStateItem<Extract<RecordValue, { groupV2: unknown }>> {
    if (this.type !== IdentifierType.GROUPV2) {
      return false;
    }
    assert(this.record.groupV2 != null, 'consistency check');

    const masterKey = this.record.groupV2.masterKey;
    if (!masterKey) {
      return false;
    }

    return group.masterKey.equals(masterKey);
  }

  public isContact(
    device: Device,
    serviceIdKind: ServiceIdKind,
  ): this is StorageStateItem<Extract<RecordValue, { contact: unknown }>> {
    if (this.type !== IdentifierType.CONTACT) {
      return false;
    }
    assert(this.record.contact != null, 'consistency check');

    if (serviceIdKind === ServiceIdKind.ACI) {
      const existingAci = this.record.contact.aciBinary;
      if (!existingAci?.length) {
        return false;
      }

      return Buffer.compare(existingAci, device.aciRawUuid) === 0;
    }

    const existingPni = this.record.contact.pniBinary;
    if (!existingPni?.length) {
      return false;
    }

    return Buffer.compare(existingPni, device.pniRawUuid) === 0;
  }

  public inspect(): string {
    return [
      `type: ${this.type}`,
      `key: ${this.key.toString('base64')}`,
      ...JSON.stringify(this.record, null, 2).split(/\n/g),
    ]
      .map((line) => `  ${line}`)
      .join('\n');
  }

  public toRecord(): StorageStateRecord<Value> {
    return {
      type: this.type,
      key: this.key,
      record: this.record,
    };
  }
}

const EMPTY_CONTACT: Proto.ContactRecord.Params = {
  e164: null,
  profileKey: null,
  identityKey: null,
  identityState: null,
  givenName: null,
  familyName: null,
  username: null,
  blocked: null,
  whitelisted: null,
  archived: null,
  markedUnread: null,
  mutedUntilTimestamp: null,
  hideStory: null,
  unregisteredAtTimestamp: null,
  systemGivenName: null,
  systemFamilyName: null,
  systemNickname: null,
  hidden: null,
  pniSignatureVerified: null,
  nickname: null,
  note: null,
  avatarColor: null,
  aciBinary: null,
  pniBinary: null,
};

const EMPTY_GROUP: Proto.GroupV2Record.Params = {
  masterKey: null,
  blocked: null,
  whitelisted: null,
  archived: null,
  markedUnread: null,
  mutedUntilTimestamp: null,
  dontNotifyForMentionsIfMuted: null,
  hideStory: null,
  storySendMode: null,
  avatarColor: null,
};

export class StorageState {
  private readonly items: ReadonlyArray<StorageStateItem>;

  constructor(
    public readonly version: bigint,
    items: ReadonlyArray<StorageStateRecord>,
  ) {
    this.items = items.map((options) => new StorageStateItem(options));
  }

  public static getEmpty(): StorageState {
    return new StorageState(0n, [
      new StorageStateItem({
        key: StorageState.createStorageID(),
        type: IdentifierType.ACCOUNT,
        record: {
          record: 'account',
          account: {
            profileKey: null,
            givenName: null,
            familyName: null,
            avatarUrlPath: null,
            noteToSelfArchived: null,
            readReceipts: null,
            sealedSenderIndicators: null,
            typingIndicators: null,
            noteToSelfMarkedUnread: null,
            linkPreviews: null,
            phoneNumberSharingMode: null,
            unlistedPhoneNumber: null,
            pinnedConversations: null,
            preferContactAvatars: null,
            payments: null,
            universalExpireTimer: null,
            preferredReactionEmoji: null,
            donorSubscriberId: null,
            donorSubscriberCurrencyCode: null,
            displayBadgesOnProfile: null,
            donorSubscriptionManuallyCancelled: null,
            keepMutedChatsArchived: null,
            hasSetMyStoriesPrivacy: null,
            hasViewedOnboardingStory: null,
            storiesDisabled: null,
            storyViewReceiptsEnabled: null,
            hasSeenGroupStoryEducationSheet: null,
            username: null,
            hasCompletedUsernameOnboarding: null,
            usernameLink: null,
            hasBackup: null,
            backupTier: null,
            backupSubscriberData: null,
            avatarColor: null,
            notificationProfileManualOverride: null,
            notificationProfileSyncDisabled: null,
          },
        },
      }),
    ]);
  }

  //
  // Account
  //

  public getAccountRecord(): Proto.AccountRecord.Params | undefined {
    const item = this.items.find((item) => item.isAccount());
    if (!item) {
      return undefined;
    }

    return item.record.account;
  }

  public updateAccount(
    diff: Partial<Proto.AccountRecord.Params>,
  ): StorageState {
    return this.updateItem(
      (item) => item.isAccount(),
      (record) => {
        return {
          record: 'account',
          account: {
            ...record.account,
            ...diff,
          },
        };
      },
    );
  }

  public updateManyAccounts(
    diff: Partial<Proto.AccountRecord.Params>,
  ): StorageState {
    return this.updateManyItems(
      (item) => item.isAccount(),
      (record) => {
        return {
          record: 'account',
          account: {
            ...record.account,
            ...diff,
          },
        };
      },
    );
  }

  //
  // Group
  //

  public getGroup(group: Group): Proto.GroupV2Record.Params | undefined {
    const item = this.items.find((item) => item.isGroup(group));
    if (!item) {
      return undefined;
    }

    return item.record.groupV2;
  }

  public addGroup(
    group: Group,
    diff: Partial<Proto.GroupV2Record.Params> = {},
  ): StorageState {
    return this.addItem({
      type: IdentifierType.GROUPV2,
      record: {
        groupV2: {
          ...EMPTY_GROUP,
          ...diff,
          masterKey: group.masterKey,
        },
      },
    });
  }

  public updateGroup(
    group: Group,
    diff: Partial<Proto.GroupV2Record.Params>,
  ): StorageState {
    return this.updateItem(
      (item) => item.isGroup(group),
      (record) => {
        return {
          groupV2: {
            ...record.groupV2,
            ...diff,
          },
        };
      },
    );
  }
  public pinGroup(group: Group): StorageState {
    return this.changeGroupPin(group, true);
  }

  public unpinGroup(group: Group): StorageState {
    return this.changeGroupPin(group, false);
  }

  public isGroupPinned(group: Group): boolean {
    const account = this.getAccountRecord();
    assert(account, 'No account record found');

    return (account.pinnedConversations ?? []).some((convo) => {
      if (convo.identifier?.groupMasterKey == null) {
        return false;
      }
      return group.masterKey.equals(convo.identifier.groupMasterKey);
    });
  }

  //
  // Contacts
  //

  public addContact(
    { device }: PrimaryDevice,
    diff: Partial<Proto.ContactRecord.Params> = {},
    serviceIdKind = ServiceIdKind.ACI,
  ): StorageState {
    return this.addItem({
      type: IdentifierType.CONTACT,
      record: {
        contact: {
          ...EMPTY_CONTACT,
          aciBinary:
            serviceIdKind === ServiceIdKind.ACI ? device.aciRawUuid : null,
          pniBinary:
            serviceIdKind === ServiceIdKind.PNI ? device.pniRawUuid : null,
          e164: device.number,
          ...diff,
        },
      },
    });
  }

  public updateContact(
    { device }: PrimaryDevice,
    diff: Partial<Proto.ContactRecord.Params>,
    serviceIdKind = ServiceIdKind.ACI,
  ): StorageState {
    return this.updateItem(
      (item) => item.isContact(device, serviceIdKind),
      (record) => {
        return {
          record: 'contact',
          contact: {
            ...record.contact,
            ...diff,
          },
        };
      },
    );
  }

  public getContact(
    { device }: PrimaryDevice,
    serviceIdKind = ServiceIdKind.ACI,
  ): Proto.ContactRecord.Params | undefined {
    const item = this.items.find((item) =>
      item.isContact(device, serviceIdKind),
    );
    if (!item) {
      return undefined;
    }

    return item.record.contact;
  }

  public removeContact(
    { device }: PrimaryDevice,
    serviceIdKind = ServiceIdKind.ACI,
  ): StorageState {
    return this.removeItem((item) => item.isContact(device, serviceIdKind));
  }

  public mergeContact(
    primary: PrimaryDevice,
    diff: Partial<Proto.ContactRecord.Params>,
  ): StorageState {
    const { device } = primary;
    return this.removeItem((item) => item.isContact(device, ServiceIdKind.ACI))
      .removeItem((item) => item.isContact(device, ServiceIdKind.PNI))
      .addContact(primary, {
        pniBinary: device.pniRawUuid,
        ...diff,
      })
      .unpin(primary, ServiceIdKind.PNI);
  }

  public pin(
    primary: PrimaryDevice,
    serviceIdKind = ServiceIdKind.ACI,
  ): StorageState {
    return this.changePin(primary, serviceIdKind, true);
  }

  public unpin(
    primary: PrimaryDevice,
    serviceIdKind = ServiceIdKind.ACI,
  ): StorageState {
    return this.changePin(primary, serviceIdKind, false);
  }

  public isPinned({ device }: PrimaryDevice): boolean {
    const account = this.getAccountRecord();
    assert(account, 'No account record found');

    return (account.pinnedConversations ?? []).some((convo) => {
      if (convo.identifier?.contact == null) {
        return false;
      }
      const existing = convo.identifier.contact.serviceIdBinary;
      return existing && Buffer.compare(existing, device.aciRawUuid) === 0;
    });
  }

  //
  // Raw record access
  //

  public addRecord(newRecord: StorageStateNewRecord): StorageState {
    return this.addItem(newRecord);
  }

  public findRecord<Value extends RecordValue>(
    find: StorageRecordPredicate<Value>,
  ): StorageStateRecord<Value> | undefined {
    const item = this.items.find((item): item is StorageStateItem<Value> => {
      return find(item.toRecord());
    });

    return item?.toRecord();
  }

  public filterRecords<Value extends RecordValue>(
    filter: StorageRecordPredicate<Value>,
  ): ReadonlyArray<StorageStateRecord<Value>> {
    return this.items.filter((item): item is StorageStateItem<Value> =>
      filter(item.toRecord()),
    );
  }

  public hasRecord(find: (record: StorageStateRecord) => boolean): boolean {
    return (
      this.findRecord(find as StorageRecordPredicate<RecordValue>) !== undefined
    );
  }

  public updateRecord<Value extends RecordValue>(
    find: StorageRecordPredicate<Value>,
    map: StorageRecordMapper<Value>,
  ): StorageState {
    return this.updateItem(
      (item): item is StorageStateItem<Value> => find(item.toRecord()),
      map,
    );
  }

  public updateManyRecords<Value extends RecordValue>(
    filter: StorageRecordPredicate<Value>,
    map: StorageRecordMapper<Value>,
  ): StorageState {
    return this.updateManyItems(
      (item): item is StorageStateItem<Value> => filter(item.toRecord()),
      map,
    );
  }

  public removeRecord(
    find: (record: StorageStateRecord) => boolean,
  ): StorageState {
    return this.removeItem((item) => find(item.toRecord()));
  }

  public removeManyRecords(
    filter: (record: StorageStateRecord) => boolean,
  ): StorageState {
    return this.removeManyItems((item) => filter(item.toRecord()));
  }

  public getAllGroupRecords(): ReadonlyArray<
    StorageStateRecord<Extract<RecordValue, { groupV2: unknown }>>
  > {
    return this.items
      .filter(
        (
          item,
        ): item is StorageStateItem<
          Extract<RecordValue, { groupV2: unknown }>
        > => item.type === IdentifierType.GROUPV2,
      )
      .map((item) => item.toRecord());
  }

  public hasKey(storageKey: Buffer): boolean {
    return this.hasRecord((item) => item.key.equals(storageKey));
  }

  //
  // General
  //

  public createWriteOperation({
    storageKey,
    recordIkm,
    previous,
  }: CreateWriteOperationOptions): Proto.WriteOperation.Params {
    const newVersion = previous ? previous.version + 1n : this.version + 1n;

    const keysToDelete = new Set(
      (previous?.items ?? []).map((item) => {
        return item.getKeyString();
      }),
    );
    const insertItem = new Array<Proto.StorageItem.Params>();

    for (const item of this.items) {
      if (!keysToDelete.delete(item.getKeyString())) {
        insertItem.push(item.toStorageItem({ storageKey, recordIkm }));
      }
    }

    const manifest = encryptStorageManifest(storageKey, {
      version: newVersion,
      identifiers: this.items.map((item) => item.toIdentifier()),
      recordIkm: recordIkm ?? null,
      sourceDevice: null,
    });

    return {
      manifest,
      insertItem,
      deleteKey: Array.from(keysToDelete).map((key) => {
        return Buffer.from(key, 'base64');
      }),
      clearAll: null,
    };
  }

  public inspect(): string {
    return [
      `version: ${this.version}`,
      ...this.items.map((item) => item.inspect()),
    ].join('\n');
  }

  public diff(oldState: StorageState): DiffResult {
    const addedIds = new Map<string, RecordValue>();
    const removedIds = new Map<string, RecordValue>();

    for (const item of this.items) {
      addedIds.set(item.key.toString('base64'), item.record);
    }

    for (const item of oldState.items) {
      const keyString = item.key.toString('base64');
      if (!addedIds.delete(keyString)) {
        removedIds.set(keyString, item.record);
      }
    }

    return {
      added: Array.from(addedIds.values()),
      removed: Array.from(removedIds.values()),
    };
  }

  //
  // Private
  //

  private addItem(newRecord: StorageStateNewRecord): StorageState {
    return this.replaceItem(this.items.length, newRecord);
  }

  private findItemIndex(
    find: (record: StorageStateItem, index: number) => boolean,
  ): number {
    const itemIndex = this.items.findIndex(find);
    if (itemIndex === -1) {
      throw new Error('Item not found');
    }
    const otherIndex = this.items.findLastIndex(find);
    if (otherIndex !== itemIndex) {
      throw new Error('Found multiple items');
    }
    return itemIndex;
  }

  private updateItem<Value extends RecordValue>(
    find: StorageItemPredicate<Value>,
    map: StorageRecordMapper<Value>,
  ): StorageState {
    const itemIndex = this.findItemIndex(find);
    const item = this.items[itemIndex] as StorageStateItem<Value> | undefined;
    assert(item, 'consistency check');

    return this.replaceItem(itemIndex, {
      type: item.type,
      record: map(item.record),
    });
  }

  public updateManyItems<Value extends RecordValue>(
    filter: StorageItemPredicate<Value>,
    map: StorageRecordMapper<Value>,
  ): StorageState {
    let updated = 0;
    const newItems = this.items.map((item, index) => {
      if (filter(item, index)) {
        updated += 1;
        return new StorageStateItem({
          type: item.type,
          key: StorageState.createStorageID(),
          record: map(item.record),
        });
      } else {
        return item;
      }
    });
    if (updated === 0) {
      throw new Error('No items updated');
    }
    return new StorageState(this.version, newItems);
  }

  private replaceItem(
    index: number,
    {
      type,
      record,
      key = StorageState.createStorageID(),
    }: StorageStateNewRecord,
  ): StorageState {
    const newItems = [
      ...this.items.slice(0, index),
      new StorageStateItem({ type, key, record }),
      ...this.items.slice(index + 1),
    ];

    return new StorageState(this.version, newItems);
  }

  private removeItem(
    find: (item: StorageStateItem, index: number) => boolean,
  ): StorageState {
    const itemIndex = this.findItemIndex(find);

    const newItems = [
      ...this.items.slice(0, itemIndex),
      ...this.items.slice(itemIndex + 1),
    ];

    return new StorageState(this.version, newItems);
  }

  private removeManyItems(
    filter: (item: StorageStateItem, index: number) => boolean,
  ): StorageState {
    const newItems = this.items.filter((item, index) => {
      return !filter(item, index);
    });
    if (newItems.length === this.items.length) {
      throw new Error('No items removed');
    }
    return new StorageState(this.version, newItems);
  }

  private changePin(
    { device }: PrimaryDevice,
    serviceIdKind: ServiceIdKind,
    isPinned: boolean,
  ): StorageState {
    const deviceServiceIdBinary =
      device.getServiceIdBinaryByKind(serviceIdKind);

    return this.updateItem(
      (item) => item.isAccount(),
      (record) => {
        const { account } = record;

        const { pinnedConversations } = account;

        const newPinnedConversations = pinnedConversations?.slice() ?? [];

        const existingIndex = newPinnedConversations.findIndex((convo) => {
          if (convo.identifier?.contact == null) {
            return false;
          }
          const existing = convo.identifier.contact.serviceIdBinary;
          return (
            existing && Buffer.compare(existing, deviceServiceIdBinary) === 0
          );
        });

        if (isPinned && existingIndex === -1) {
          newPinnedConversations.push({
            identifier: {
              contact: {
                e164: null,
                serviceIdBinary: deviceServiceIdBinary,
              },
            },
          });
        } else if (!isPinned && existingIndex !== -1) {
          newPinnedConversations.splice(existingIndex, 1);
        }

        return {
          account: {
            ...account,
            pinnedConversations: newPinnedConversations,
          },
        };
      },
    );
  }

  private changeGroupPin(group: Group, isPinned: boolean): StorageState {
    return this.updateItem(
      (item) => item.isAccount(),
      (record) => {
        const { account } = record;
        const { pinnedConversations } =
          account satisfies Proto.AccountRecord.Params;

        const newPinnedConversations = pinnedConversations?.slice() ?? [];

        const existingIndex = newPinnedConversations.findIndex((convo) => {
          if (convo.identifier?.groupMasterKey == null) {
            return false;
          }
          return group.masterKey.equals(convo.identifier.groupMasterKey);
        });

        if (isPinned && existingIndex === -1) {
          newPinnedConversations.push({
            identifier: {
              groupMasterKey: group.masterKey,
            },
          });
        } else if (!isPinned && existingIndex !== -1) {
          newPinnedConversations.splice(existingIndex, 1);
        }

        return {
          account: {
            ...account,
            pinnedConversations: newPinnedConversations,
          },
        };
      },
    );
  }

  private static createStorageID(): Buffer {
    return crypto.randomBytes(KEY_SIZE);
  }
}
