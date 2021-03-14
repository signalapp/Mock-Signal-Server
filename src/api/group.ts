// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import {
  ClientZkGroupCipher,
  GroupSecretParams,
  ProfileKey,
  ProfileKeyCredentialPresentation,
} from '@signalapp/signal-client/zkgroup';

import { signalservice as Proto } from '../../protos/compiled';
import { UUID } from '../types';
import { Group as GroupData } from '../data/group';

const AccessRequired = Proto.AccessControl.AccessRequired;

export type GroupMember = Readonly<{
  presentation: ProfileKeyCredentialPresentation;
  profileKey: ProfileKey;
  uuid: UUID;
}>;

export type GroupOptions = Readonly<{
  secretParams: GroupSecretParams;
  title: string;
  members: ReadonlyArray<GroupMember>;
}>;

export class Group extends GroupData {
  private privRevision = 0;
  private readonly secretParams: GroupSecretParams;
  private readonly cipher: ClientZkGroupCipher;

  public readonly title: string;

  constructor({ secretParams, title, members }: GroupOptions) {
    super();

    this.secretParams = secretParams;
    this.cipher = new ClientZkGroupCipher(this.secretParams);
    this.title = title;

    this.privPublicParams = this.secretParams.getPublicParams();

    // Build group log

    this.privChanges = {
      groupChanges: [ {
        groupState: {
          publicKey: this.publicParams.serialize(),
          version: this.revision,
          title: this.encryptBlob({ title }),

          // TODO(indutny): make it configurable
          accessControl: {
            attributes: AccessRequired.MEMBER,
            members: AccessRequired.MEMBER,
            addFromInviteLink: AccessRequired.UNSATISFIABLE,
          },

          members: members.map(({ uuid, profileKey, presentation }) => {
            return {
              role: Proto.Member.Role.ADMINISTRATOR,
              userId: this.cipher.encryptUuid(uuid).serialize(),
              profileKey: this.cipher.encryptProfileKey(profileKey, uuid)
                .serialize(),
              presentation: presentation.serialize(),
            };
          }),
        },
      } ],
    };
  }

  public get revision(): number {
    return this.privRevision;
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

  //
  // Private
  //

  private encryptBlob(
    proto: Proto.IGroupAttributeBlob,
  ): Buffer {
    const plaintext = Proto.GroupAttributeBlob.encode(proto).finish();
    return this.cipher.encryptBlob(Buffer.from(plaintext));
  }
}
