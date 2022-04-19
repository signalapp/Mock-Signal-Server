// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import assert from 'assert';
import {
  ClientZkGroupCipher,
  GroupSecretParams,
  ProfileKey,
  ProfileKeyCredentialPresentation,
} from '@signalapp/libsignal-client/zkgroup';

import { signalservice as Proto } from '../../protos/compiled';
import { UUID } from '../types';
import { Group as GroupData } from '../data/group';

const AccessRequired = Proto.AccessControl.AccessRequired;

export type GroupOptions = Readonly<{
  secretParams: GroupSecretParams;

  groupState: Proto.IGroup;
}>;

export type GroupMember = Readonly<{
  presentation: ProfileKeyCredentialPresentation;
  profileKey: ProfileKey;
  uuid: UUID;
}>;

export type GroupFromConfigOptions = Readonly<{
  secretParams: GroupSecretParams;

  title: string;
  members: ReadonlyArray<GroupMember>;
}>;

function encryptBlob(
  cipher: ClientZkGroupCipher,
  proto: Proto.IGroupAttributeBlob,
): Buffer {
  const plaintext = Proto.GroupAttributeBlob.encode(proto).finish();
  return cipher.encryptBlob(Buffer.from(plaintext));
}

function decryptBlob(
  cipher: ClientZkGroupCipher,
  ciphertext: Uint8Array,
): Proto.IGroupAttributeBlob {
  const plaintext = cipher.decryptBlob(Buffer.from(ciphertext));
  return Proto.GroupAttributeBlob.decode(plaintext);
}

export class Group extends GroupData {
  public readonly secretParams: GroupSecretParams;
  public readonly title: string;

  constructor({ secretParams, groupState }: GroupOptions) {
    super();

    assert.ok(groupState.title, 'Group must have a title blob');

    this.secretParams = secretParams;

    const cipher = new ClientZkGroupCipher(secretParams);
    this.title = decryptBlob(cipher, groupState.title)?.title ?? '';

    this.privPublicParams = this.secretParams.getPublicParams();

    // Build group log

    this.privChanges = {
      groupChanges: [ {
        groupState,
      } ],
    };
  }

  public static fromConfig(
    { secretParams, title, members }: GroupFromConfigOptions,
  ): Group {
    const cipher = new ClientZkGroupCipher(secretParams);

    const groupState = {
      publicKey: secretParams.getPublicParams().serialize(),
      version: 0,
      title: encryptBlob(cipher, { title }),

      // TODO(indutny): make it configurable
      accessControl: {
        attributes: AccessRequired.MEMBER,
        members: AccessRequired.MEMBER,
        addFromInviteLink: AccessRequired.UNSATISFIABLE,
      },

      members: members.map(({ presentation }) => {
        return {
          role: Proto.Member.Role.ADMINISTRATOR,
          presentation: presentation.serialize(),
        };
      }),
    };

    return new Group({
      secretParams,
      groupState,
    });
  }

  public get masterKey(): Buffer {
    return this.secretParams.getMasterKey().serialize();
  }

  public toContext(): Proto.IGroupContextV2 {
    const masterKey = this.masterKey;
    return {
      masterKey,
      revision: this.revision,
    };
  }
}
