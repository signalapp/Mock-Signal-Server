// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import { CallingRoomId } from '../calling';

export type CallDataOptions = Readonly<{
  roomId: CallingRoomId | null;
}>;

export abstract class CallData {
  #roomId: CallingRoomId | null;

  constructor(options: CallDataOptions) {
    this.#roomId = options.roomId;
  }

  public get roomId(): CallingRoomId | null {
    return this.#roomId;
  }
}
