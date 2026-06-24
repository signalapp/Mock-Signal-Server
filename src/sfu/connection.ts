// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import { CallingDemuxId, CallingEraId } from '../calling';
import { IcePassword } from './ice';
import { StrpKeyMaterial } from './srtp';

export type SfuConnectionId = `${CallingEraId}:${CallingDemuxId}` & {
  SfuConnectionId: never;
};

export function getSfuConnectionId(params: {
  eraId: CallingEraId;
  demuxId: CallingDemuxId;
}): SfuConnectionId {
  return `${params.eraId}:${params.demuxId}` as SfuConnectionId;
}

export type SfuConnectionOptions = Readonly<{
  connectionId: SfuConnectionId;
  demuxId: CallingDemuxId;
  serverIceUsername: string;
  clientIceUsername: string;
  serverIcePassword: IcePassword;
  clientIcePassword: IcePassword;
  strpKeyMaterial: StrpKeyMaterial;
}>;

export class SfuConnection {
  #connectionId: SfuConnectionId;
  #demuxId: CallingDemuxId;
  #serverIceUsername: string;
  #clientIceUsername: string;
  #serverIcePassword: IcePassword;
  #clientIcePassword: IcePassword;
  #strpKeyMaterial: StrpKeyMaterial;

  constructor(options: SfuConnectionOptions) {
    this.#connectionId = options.connectionId;
    this.#demuxId = options.demuxId;
    this.#serverIceUsername = options.serverIceUsername;
    this.#clientIceUsername = options.clientIceUsername;
    this.#serverIcePassword = options.serverIcePassword;
    this.#clientIcePassword = options.clientIcePassword;
    this.#strpKeyMaterial = options.strpKeyMaterial;
  }

  get connectionId(): SfuConnectionId {
    return this.#connectionId;
  }

  get demuxId(): CallingDemuxId {
    return this.#demuxId;
  }

  get serverIceUsername(): string {
    return this.#serverIceUsername;
  }

  get clientIceUsername(): string {
    return this.#clientIceUsername;
  }

  get serverIcePassword(): IcePassword {
    return this.#serverIcePassword;
  }

  get clientIcePassword(): IcePassword {
    return this.#clientIcePassword;
  }

  get strpKeyMaterial(): StrpKeyMaterial {
    return this.#strpKeyMaterial;
  }
}
