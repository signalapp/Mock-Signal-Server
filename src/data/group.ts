// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import assert from 'assert';
import { GroupPublicParams } from '@signalapp/signal-client/zkgroup';

import { signalservice as Proto } from '../../protos/compiled';

export abstract class Group {
  protected privChanges?: Proto.IGroupChanges;
  protected privPublicParams?: GroupPublicParams;

  public get changes(): Proto.IGroupChanges {
    assert(this.privChanges !== undefined, 'Group not initialized');
    return this.privChanges;
  }

  public get publicParams(): GroupPublicParams {
    assert(this.privPublicParams !== undefined, 'Group not initialized');
    return this.privPublicParams;
  }

  public getState(): Proto.IGroup {
    const state = this.changes.groupChanges?.[0].groupState;
    assert(state, 'Group must have initial state');
    return state;
  }

  public getChangesSince(since: number): Proto.IGroupChanges {
    return {
      groupChanges: this.changes.groupChanges?.slice(since),
    };
  }
}
