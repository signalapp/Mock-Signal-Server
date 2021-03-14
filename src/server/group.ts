// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import assert from 'assert';
import {
  GroupPublicParams,
  ProfileKeyCredentialPresentation,
  ServerZkAuthOperations,
  ServerZkProfileOperations,
} from '@signalapp/signal-client/zkgroup';

import { signalservice as Proto } from '../../protos/compiled';
import { Group } from '../data/group';

export type ServerGroupOptions = Readonly<{
  authOps: ServerZkAuthOperations;
  profileOps: ServerZkProfileOperations;
  state: Proto.IGroup,
}>;

export class ServerGroup extends Group {
  private readonly profileOps: ServerZkProfileOperations;

  constructor({ profileOps, state }: ServerGroupOptions) {
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

    for (const { role, presentation } of state.members) {
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
    }

    this.privChanges = {
      groupChanges: [ {
        groupState: state,
      } ],
    };
  }
}
