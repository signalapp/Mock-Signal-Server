// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import assert from 'assert';
import crypto from 'crypto';
import Long from 'long';

import { signalservice as Proto } from '../../protos/compiled';
import {
  encryptStorageItem,
  encryptStorageManifest,
} from '../crypto';
import { Device } from '../data/device';
import { ServiceIdKind } from '../types';
import { Group } from './group';
import { PrimaryDevice } from './primary-device';

export type StorageStateRecord = Readonly<{
  type: Proto.ManifestRecord.Identifier.Type;
  key: Buffer;
  record: Proto.IStorageRecord;
}>;

export type StorageStateNewRecord = Readonly<{
  type: Proto.ManifestRecord.Identifier.Type;
  key?: Buffer;
  record: Proto.IStorageRecord;
}>;

export type DiffResult = Readonly<{
  added: ReadonlyArray<Proto.IStorageRecord>;
  removed: ReadonlyArray<Proto.IStorageRecord>;
}>;

const KEY_SIZE = 16;

const IdentifierType = Proto.ManifestRecord.Identifier.Type;
type IdentifierType = Proto.ManifestRecord.Identifier.Type;

class StorageStateItem {
  public readonly type: IdentifierType;
  public readonly key: Buffer;
  public readonly record: Proto.IStorageRecord;

  constructor({
    type,
    key,
    record,
  }: StorageStateRecord) {
    this.type = type;
    this.key = key;
    this.record = record;
  }

  public getKeyString(): string {
    return this.key.toString('base64');
  }

  public toStorageItem(storageKey: Buffer): Proto.IStorageItem {
    return encryptStorageItem(storageKey, this.key, this.record);
  }

  public toIdentifier(): Proto.ManifestRecord.IIdentifier {
    return {
      type: this.type,
      raw: this.key,
    };
  }

  public isAccount(): boolean {
    return this.type === IdentifierType.ACCOUNT && Boolean(this.record.account);
  }

  public isGroup(group: Group): boolean {
    if (this.type !== IdentifierType.GROUPV2) {
      return false;
    }

    const masterKey = this.record?.groupV2?.masterKey;
    if (!masterKey) {
      return false;
    }

    return group.masterKey.equals(masterKey);
  }

  public isContact(device: Device, serviceIdKind: ServiceIdKind): boolean {
    if (this.type !== IdentifierType.CONTACT) {
      return false;
    }

    const serviceId = serviceIdKind === ServiceIdKind.ACI ?
      this.record?.contact?.aci : this.record?.contact?.pni;
    if (!serviceId) {
      return false;
    }

    return serviceId === device.getServiceIdByKind(serviceIdKind);
  }

  public inspect(): string {
    return [
      `type: ${this.type}`,
      `key: ${this.key.toString('base64')}`,
      ...JSON.stringify(this.record, null, 2).split(/\n/g),
    ].map((line) => `  ${line}`).join('\n');
  }

  public toRecord(): StorageStateRecord {
    return {
      type: this.type,
      key: this.key,
      record: this.record,
    };
  }
}

export class StorageState {
  private readonly items: ReadonlyArray<StorageStateItem>;

  constructor(
    public readonly version: number,
    items: ReadonlyArray<StorageStateRecord>,
  ) {
    this.items = items.map((options) => new StorageStateItem(options));
  }

  public static getEmpty(): StorageState {
    return new StorageState(0, [
      new StorageStateItem({
        key: StorageState.createStorageID(),
        type: IdentifierType.ACCOUNT,
        record: {
          account: {},
        },
      }),
    ]);
  }

  //
  // Account
  //

  public getAccountRecord(): Proto.IAccountRecord | undefined {
    const item = this.items.find((item) => item.isAccount());
    if (!item) {
      return undefined;
    }

    const { account } = item.record;
    assert(account, 'consistency check');

    return account;
  }

  public updateAccount(diff: Proto.IAccountRecord): StorageState {
    return this.updateItem(
      (item) => item.isAccount(),
      ({ account }) => ({
        account: {
          ...account,
          ...diff,
        },
      }),
    );
  }

  //
  // Group
  //

  public getGroup(group: Group): Proto.IGroupV2Record | undefined {
    const item = this.items.find((item) => item.isGroup(group));
    if (!item) {
      return undefined;
    }

    const { groupV2 } = item.record;
    assert(groupV2, 'consistency check');

    return groupV2;
  }

  public addGroup(
    group: Group,
    diff: Proto.IGroupV2Record = {},
  ): StorageState {
    return this.addItem({
      type: IdentifierType.GROUPV2,
      record: {
        groupV2: {
          ...diff,
          masterKey: group.masterKey,
        },
      },
    });
  }

  public updateGroup(
    group: Group,
    diff: Proto.IGroupV2Record,
  ): StorageState {
    return this.updateItem(
      (item) => item.isGroup(group),
      ({ groupV2 }) => ({
        groupV2: {
          ...groupV2,
          ...diff,
        },
      }),
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

    return (account.pinnedConversations || []).some((convo) => {
      if (!convo.groupMasterKey) {
        return false;
      }
      return group.masterKey.equals(convo.groupMasterKey);
    });
  }

  //
  // Contacts
  //

  public addContact(
    { device }: PrimaryDevice,
    diff: Proto.IContactRecord = {},
    serviceIdKind = ServiceIdKind.ACI,
  ): StorageState {
    return this.addItem({
      type: IdentifierType.CONTACT,
      record: {
        contact: {
          aci: serviceIdKind === ServiceIdKind.ACI ?
            device.getServiceIdByKind(serviceIdKind) : undefined,
          pni: serviceIdKind === ServiceIdKind.PNI ?
            device.getServiceIdByKind(serviceIdKind) : undefined,
          serviceE164: device.number,
          ...diff,
        },
      },
    });
  }

  public updateContact(
    { device }: PrimaryDevice,
    diff: Proto.IContactRecord,
    serviceIdKind = ServiceIdKind.ACI,
  ): StorageState {
    return this.updateItem(
      (item) => item.isContact(device, serviceIdKind),
      ({ contact }) => ({
        contact: {
          ...contact,
          ...diff,
        },
      }),
    );
  }

  public getContact(
    { device }: PrimaryDevice,
    serviceIdKind = ServiceIdKind.ACI,
  ): Proto.IContactRecord | undefined {
    const item = this.items.find(
      (item) => item.isContact(device, serviceIdKind),
    );
    if (!item) {
      return undefined;
    }

    const { contact } = item.record;
    assert(contact, 'consistency check');

    return contact;
  }

  public removeContact(
    { device }: PrimaryDevice,
    serviceIdKind = ServiceIdKind.ACI,
  ): StorageState {
    return this.removeItem(item => item.isContact(device, serviceIdKind));
  }

  public mergeContact(
    primary: PrimaryDevice,
    diff: Proto.IContactRecord,
  ): StorageState {
    const { device } = primary;
    return this
      .removeItem(item => item.isContact(device, ServiceIdKind.ACI))
      .removeItem(item => item.isContact(device, ServiceIdKind.PNI))
      .addContact(primary, {
        pni: device.getServiceIdByKind(ServiceIdKind.PNI),
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

    return (account.pinnedConversations || []).some((convo) => {
      return convo?.contact?.serviceId === device.aci;
    });
  }

  //
  // Raw record access
  //

  public addRecord(newRecord: StorageStateNewRecord): StorageState {
    return this.addItem(newRecord);
  }

  public findRecord(
    find: (record: StorageStateRecord) => boolean,
  ): StorageStateRecord | undefined {
    const item = this.items.find((item) => find(item.toRecord()));

    return item?.toRecord();
  }

  public hasRecord(
    find: (record: StorageStateRecord) => boolean,
  ): boolean {
    return this.findRecord(find) !== undefined;
  }

  public updateRecord(
    find: (item: StorageStateRecord) => boolean,
    map: (record: Proto.IStorageRecord) => Proto.IStorageRecord,
  ): StorageState {
    return this.updateItem(
      (item) => find(item.toRecord()),
      map,
    );
  }

  public removeRecord(
    find: (item: StorageStateRecord) => boolean,
  ): StorageState {
    return this.removeItem((item) => find(item.toRecord()));
  }

  public getAllGroupRecords(
  ): ReadonlyArray<StorageStateRecord> {
    return this.items
      .filter((item) => item.type === IdentifierType.GROUPV2)
      .map((item) => item.toRecord());
  }

  public hasKey(storageKey: Buffer): boolean {
    return this.hasRecord(({ key }) => key?.equals(storageKey));
  }

  //
  // General
  //

  public createWriteOperation(
    storageKey: Buffer,
    previous?: StorageState,
  ): Proto.IWriteOperation {
    const newVersion = Long.fromNumber(
      previous ? previous.version + 1 : this.version + 1,
    );

    const keysToDelete = new Set((previous?.items ?? []).map((item) => {
      return item.getKeyString();
    }));
    const insertItem = new Array<Proto.IStorageItem>();

    for (const item of this.items) {
      if (!keysToDelete.delete(item.getKeyString())) {
        insertItem.push(item.toStorageItem(storageKey));
      }
    }

    const manifest = encryptStorageManifest(storageKey, {
      version: newVersion,
      keys: this.items.map((item) => item.toIdentifier()),
    });

    return {
      manifest,
      insertItem,
      deleteKey: Array.from(keysToDelete).map((key) => {
        return Buffer.from(key, 'base64');
      }),
    };
  }

  public inspect(): string {
    return [
      `version: ${this.version}`,
      ...this.items.map((item) => item.inspect()),
    ].join('\n');
  }

  public diff(oldState: StorageState): DiffResult {
    const addedIds = new Map<string, Proto.IStorageRecord>();
    const removedIds = new Map<string, Proto.IStorageRecord>();

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

  private updateItem(
    find: (item: StorageStateItem, index: number) => boolean,
    map: (record: Proto.IStorageRecord) => Proto.IStorageRecord,
  ): StorageState {
    const itemIndex = this.items.findIndex(find);
    if (itemIndex === -1) {
      throw new Error('Item not found');
    }

    const item = this.items[itemIndex];
    assert(item, 'consistency check');

    return this.replaceItem(itemIndex, {
      type: item.type,
      record: map(item.record),
    });
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
    find: (item: StorageStateItem) => boolean,
  ): StorageState {
    const itemIndex = this.items.findIndex((item) => find(item));
    if (itemIndex === -1) {
      throw new Error('Record not found');
    }

    const newItems = [
      ...this.items.slice(0, itemIndex),
      ...this.items.slice(itemIndex + 1),
    ];

    return new StorageState(this.version, newItems);
  }

  private changePin(
    { device }: PrimaryDevice,
    serviceIdKind: ServiceIdKind,
    isPinned: boolean,
  ): StorageState {
    const deviceServiceId = device.getServiceIdByKind(serviceIdKind);

    return this.updateItem(
      (item) => item.isAccount(),
      ({ account }) => {
        assert(account, 'consistency check');

        const { pinnedConversations } = account;

        const newPinnedConversations = pinnedConversations?.slice() || [];

        const existingIndex = newPinnedConversations.findIndex((convo) => {
          return convo?.contact?.serviceId === deviceServiceId;
        });

        if (isPinned && existingIndex === -1) {
          newPinnedConversations.push({
            contact: { serviceId: deviceServiceId },
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
      ({ account }) => {
        assert(account, 'consistency check');

        const { pinnedConversations } = account;

        const newPinnedConversations = pinnedConversations?.slice() || [];

        const existingIndex = newPinnedConversations.findIndex((convo) => {
          if (!convo.groupMasterKey) {
            return false;
          }
          return group.masterKey.equals(convo.groupMasterKey);
        });

        if (isPinned && existingIndex === -1) {
          newPinnedConversations.push({
            groupMasterKey: group.masterKey,
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
