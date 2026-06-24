// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import { CallData, CallDataOptions } from '../data/call';
import { CallingEraId, CallingRoomId, CallingUserId } from '../calling';

export type ServerCallOptions = Readonly<
  CallDataOptions & {
    roomId: CallingRoomId;
    eraId: CallingEraId;
    creatorUserId: CallingUserId;
  }
>;

export class ServerCall extends CallData {
  #roomId: CallingRoomId;
  #eraId: CallingEraId;
  #creatorUserId: CallingUserId;

  constructor(options: ServerCallOptions) {
    super(options);
    this.#roomId = options.roomId;
    this.#eraId = options.eraId;
    this.#creatorUserId = options.creatorUserId;
  }

  public override get roomId(): CallingRoomId {
    return this.#roomId;
  }

  public get eraId(): CallingEraId {
    return this.#eraId;
  }

  public get creatorUserId(): CallingUserId {
    return this.#creatorUserId;
  }
}
