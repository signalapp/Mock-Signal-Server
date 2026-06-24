// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import { SfuCall, SfuClientStatus } from './call';
import {
  CallInfo,
  CallingDemuxId,
  CallingEraId,
  CallingError,
  CallingErrorCode,
  CallingRoomId,
  CallingUserId,
  CallType,
} from '../calling';
import {
  getSfuConnectionId,
  SfuConnection,
  SfuConnectionId,
} from './connection';
import { getStrpKeyMaterial } from './srtp';
import { getIceUsernames, IcePassword, IceUsernameFragment } from './ice';
import { CallingKeyPair, CallingPublicKey } from './crypto';

export type SfuJoinCallRequest = Readonly<{
  eraId: CallingEraId;
  roomId: CallingRoomId | null;
  userId: CallingUserId;

  demuxId: CallingDemuxId;

  clientIceUsernameFragment: IceUsernameFragment;
  clientIcePassword: IcePassword;
  clientPublicKey: CallingPublicKey;
  clientHkdfExtraInfo: Uint8Array<ArrayBuffer> | null;

  serverIceUsernameFragment: IceUsernameFragment;
  serverIcePassword: IcePassword;

  callType: CallType;
  isAdmin: boolean;
  newClientsRequireApproval: boolean;
  approvedUsers: ReadonlyArray<CallingUserId> | null;
}>;

export type SfuJoinCallResponse = Readonly<{
  serverPublicKey: CallingPublicKey;
  clientStatus: SfuClientStatus;
}>;

export type SfuPeekCallRequest = Readonly<{
  eraId: CallingEraId;
  userId: CallingUserId;
}>;

export type SfuPeekCallResponse = Readonly<{
  info: CallInfo;
}>;

/**
 * Selective Forwarding Unit
 */
export class SfuService {
  #calls = new Map<CallingEraId, SfuCall>();
  #connections = new Map<SfuConnectionId, SfuConnection>();

  public async joinCall(
    request: SfuJoinCallRequest,
  ): Promise<SfuJoinCallResponse> {
    let call = this.#calls.get(request.eraId);

    if (call == null) {
      call = new SfuCall({
        creatorUserId: request.userId,
        roomId: request.roomId,
        eraId: request.eraId,
        maxClients: 30,
        newClientsRequireApproval: request.newClientsRequireApproval,
        persistApprovalForAllUsersWhoJoin: true,
        approvedUsers: request.approvedUsers,
      });

      this.#calls.set(call.eraId, call);
    }

    if (call.hasClient(request.demuxId)) {
      throw new CallingError(CallingErrorCode.DuplicateDemuxIdDetected);
    }

    const { serverIceUsername, clientIceUsername } = getIceUsernames({
      serverIceUsernameFragment: request.serverIceUsernameFragment,
      clientIceUsernameFragment: request.clientIceUsernameFragment,
    });

    const clientStatus = call.addClient({
      userId: request.userId,
      demuxId: request.demuxId,
      isAdmin: request.isAdmin,
    });

    if (clientStatus === SfuClientStatus.Rejected) {
      throw new CallingError(CallingErrorCode.TooManyClients);
    }

    const serverKeys = await CallingKeyPair.generate();
    const serverSecret = serverKeys.privateKey;
    const serverPublicKey = serverKeys.publicKey;

    const sharedSecret = serverSecret.agree(request.clientPublicKey);

    const strpKeyMaterial = getStrpKeyMaterial({
      sharedSecret,
      clientHkdfExtraInfo: request.clientHkdfExtraInfo,
    });

    const connectionId = getSfuConnectionId({
      eraId: call.eraId,
      demuxId: request.demuxId,
    });

    const connection = new SfuConnection({
      connectionId,
      demuxId: request.demuxId,
      serverIceUsername,
      clientIceUsername,
      serverIcePassword: request.serverIcePassword,
      clientIcePassword: request.clientIcePassword,
      strpKeyMaterial,
    });

    this.#connections.set(connectionId, connection);

    return {
      serverPublicKey,
      clientStatus,
    };
  }

  public async peekCall(
    request: SfuPeekCallRequest,
  ): Promise<SfuPeekCallResponse> {
    const call = this.#calls.get(request.eraId);
    if (call == null) {
      throw new CallingError(CallingErrorCode.CallNotFound);
    }

    const includePendingUserIds = call.isAdmin(request.userId);
    const info = call.getInfo(includePendingUserIds);

    return { info };
  }
}
