// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import assert from 'assert';
import {
  GroupPublicParams,
  ProfileKeyCredentialPresentation,
  ServerSecretParams,
  ServerZkProfileOperations,
  UuidCiphertext,
} from '@signalapp/libsignal-client/zkgroup';

import { signalservice as Proto } from '../../protos/compiled';
import { Group } from '../data/group';

export type ServerGroupOptions = Readonly<{
  profileOps: ServerZkProfileOperations;
  zkSecret: ServerSecretParams;
  state: Proto.IGroup,
}>;

const { AccessRequired } = Proto.AccessControl;
const { Role } = Proto.Member;

export class ServerGroup extends Group {
  private readonly profileOps: ServerZkProfileOperations;
  private readonly zkSecret: ServerSecretParams;

  constructor({ profileOps, zkSecret, state }: ServerGroupOptions) {
    super();

    // TODO(indutny): use zod or something
    assert.ok(state.publicKey, 'Group public key must be present');
    assert.strictEqual(state.version, 0, 'Initial group version must be zero');
    assert.ok(state.accessControl, 'Group access control must be present');
    assert.ok(
      typeof state.accessControl.attributes === 'number' &&
        typeof state.accessControl.members === 'number' &&
        typeof state.accessControl.addFromInviteLink === 'number',
      'Group access control must be configured',
    );
    assert.ok(
      state.members && state.members.length > 0,
      'Group members must be present',
    );

    this.privPublicParams = new GroupPublicParams(Buffer.from(state.publicKey));
    this.profileOps = profileOps;
    this.zkSecret = zkSecret;

    const unrolledState = { ...state };

    unrolledState.members = state.members.map(
      (member) => this.unrollMember(member),
    );

    this.privChanges = {
      groupChanges: [ {
        groupState: unrolledState,
      } ],
    };
  }

  public modify(
    auth: UuidCiphertext,
    actions: Proto.GroupChange.IActions,
  ): Proto.IGroupChange {
    const appliedActions: Proto.GroupChange.IActions = {
      sourceUuid: auth.serialize(),
    };

    const newState = {
      ...this.state,
    };

    const member = this.getMember(auth);
    const { accessControl } = newState;

    const changeEpoch = 1;

    if (actions.modifyTitle) {
      this.verifyAccess(
        'title',
        member,
        accessControl?.attributes ?? AccessRequired.UNKNOWN,
      );

      appliedActions.modifyTitle = actions.modifyTitle;
      newState.title = actions.modifyTitle.title;
    }

    const encodedActions = Proto.GroupChange.Actions.encode(
      appliedActions,
    ).finish();
    const serverSignature = this.zkSecret.sign(
      Buffer.from(encodedActions),
    ).serialize();

    const groupChange: Proto.IGroupChange = {
      actions: encodedActions,
      changeEpoch,
    };

    assert.ok(this.privChanges?.groupChanges, 'Must be initialized');
    this.privChanges.groupChanges.push({
      groupChange,
      groupState: newState,
    });

    return {
      ...groupChange,
      serverSignature,
    };
  }

  //
  // Private
  //

  private verifyAccess(
    attribute: string,
    member: Proto.IMember | undefined,
    access: Proto.AccessControl.AccessRequired,
  ): void {
    switch (access) {
    case AccessRequired.ANY:
      break;

    case AccessRequired.MEMBER:
      assert.ok(member, `Must be a member to access: ${attribute}`);
      break;

    case AccessRequired.ADMINISTRATOR:
      assert.strictEqual(
        member?.role,
        Role.ADMINISTRATOR,
        `Must be an administrator to modify: ${attribute}`,
      );
      break;

    case AccessRequired.UNSATISFIABLE:
      throw new Error(`Unsatisfiable access attribute: ${attribute}`);

    case AccessRequired.UNKNOWN:
      throw new Error(`Unknown access for attribute: ${attribute}`);
    }
  }

  private unrollMember({ role, presentation }: Proto.IMember): Proto.IMember {
    assert.strictEqual(
      typeof role,
      'number',
      'Group member role is undefined',
    );
    assert.ok(
      presentation,
      'Group member presentation is undefined',
    );

    const presentationFFI = new ProfileKeyCredentialPresentation(
      Buffer.from(presentation),
    );
    this.profileOps.verifyProfileKeyCredentialPresentation(
      this.publicParams,
      presentationFFI,
    );

    return {
      role,
      userId: presentationFFI.getUuidCiphertext().serialize(),
      profileKey: presentationFFI.getProfileKeyCiphertext().serialize(),
    };
  }
}
