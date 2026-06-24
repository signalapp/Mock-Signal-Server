// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import { CallData, CallDataOptions } from '../data/call';
import {
  CallInfo,
  CallInfoClient,
  CallingDemuxId,
  CallingEraId,
  CallingUserId,
} from '../calling';

export enum SfuClientStatus {
  Active = 'ACTIVE',
  Pending = 'PENDING',
  Blocked = 'BLOCKED',
  Rejected = 'REJECTED',
}

export type SfuClient = Readonly<{
  userId: CallingUserId;
  demuxId: CallingDemuxId;
  isAdmin: boolean;
}>;

function toCallInfoClients(
  clients: ReadonlyArray<SfuClient>,
): ReadonlyArray<CallInfoClient> {
  return clients.map((client) => {
    return {
      demuxId: client.demuxId,
      opaqueUserId: client.userId,
    };
  });
}

type TakeClientsResult = Readonly<{
  userId: CallingUserId;
  matches: Array<SfuClient>;
  remaining: Array<SfuClient>;
}>;

function takeClients(
  existing: ReadonlyArray<SfuClient>,
  demuxId: CallingDemuxId,
): TakeClientsResult | null {
  const found = existing.find((client) => client.demuxId === demuxId);
  if (found == null) {
    return null;
  }
  const { userId } = found;
  const matches: Array<SfuClient> = [];
  const remaining: Array<SfuClient> = [];

  for (const client of existing) {
    if (client.demuxId === demuxId) {
      matches.push(client);
    } else {
      remaining.push(client);
    }
  }

  return { userId, matches, remaining };
}

export type SfuCallOptions = Readonly<
  CallDataOptions & {
    eraId: CallingEraId;
    creatorUserId: CallingUserId;
    maxClients: number;
    newClientsRequireApproval: boolean;
    persistApprovalForAllUsersWhoJoin: boolean;
    approvedUsers: ReadonlyArray<CallingUserId> | null;
  }
>;

export class SfuCall extends CallData {
  #eraId: CallingEraId;
  #creatorUserId: CallingUserId;
  #maxClients: number;
  #newClientsRequireApproval: boolean;
  #persistApprovalForAllUsersWhoJoin: boolean;

  #activeClients: Array<SfuClient> = [];
  #pendingClients: Array<SfuClient> = [];
  #removedClients: Array<SfuClient> = [];

  #blockedUsers = new Set<string>();
  #deniedUsers = new Set<string>();
  #approvedUsers: Set<CallingUserId>;

  constructor(options: SfuCallOptions) {
    super(options);
    this.#eraId = options.eraId;
    this.#creatorUserId = options.creatorUserId;
    this.#maxClients = options.maxClients;
    this.#newClientsRequireApproval = options.newClientsRequireApproval;
    this.#persistApprovalForAllUsersWhoJoin =
      options.persistApprovalForAllUsersWhoJoin;

    this.#approvedUsers = new Set<CallingUserId>(options.approvedUsers);
  }

  public get eraId(): CallingEraId {
    return this.#eraId;
  }

  public getInfo(includePendingClients: boolean): CallInfo {
    const activeClients = toCallInfoClients(this.#activeClients);
    const pendingClients = includePendingClients
      ? toCallInfoClients(this.#pendingClients)
      : null;

    return {
      eraId: this.eraId,
      maxClients: this.#maxClients,
      creatorUserId: this.#creatorUserId,
      activeClients,
      pendingClients,
    };
  }

  public isAdmin(userId: string): boolean {
    return this.#activeClients.some((client) => {
      return client.userId === userId && client.isAdmin;
    });
  }

  public addClient(client: SfuClient): SfuClientStatus {
    const count = this.#activeClients.length + this.#pendingClients.length;
    if (count >= this.#maxClients) {
      return SfuClientStatus.Rejected;
    }

    if (this.#blockedUsers.has(client.userId)) {
      this.#removedClients.push(client);
      return SfuClientStatus.Blocked;
    }

    const canAutoJoin =
      client.isAdmin ||
      !this.#newClientsRequireApproval ||
      this.#approvedUsers.has(client.userId);

    if (canAutoJoin) {
      if (this.#persistApprovalForAllUsersWhoJoin) {
        this.#approvedUsers.add(client.userId);
      }

      this.#activeClients.push(client);
      return SfuClientStatus.Active;
    } else {
      this.#pendingClients.push(client);
      return SfuClientStatus.Pending;
    }
  }

  public hasClient(demuxId: CallingDemuxId): boolean {
    return (
      this.#activeClients.some((client) => client.demuxId === demuxId) ||
      this.#pendingClients.some((client) => client.demuxId === demuxId) ||
      this.#removedClients.some((client) => client.demuxId === demuxId)
    );
  }

  public approvePendingDemuxId(demuxId: CallingDemuxId): void {
    const result = takeClients(this.#pendingClients, demuxId);
    if (result != null) {
      this.#pendingClients = result.remaining;
      for (const client of result.matches) {
        this.#activeClients.push(client);
      }
      this.#deniedUsers.delete(result.userId);
      this.#approvedUsers.add(result.userId);
    }
  }

  public denyPendingDemuxId(demuxId: CallingDemuxId): void {
    const result = takeClients(this.#pendingClients, demuxId);
    if (result != null) {
      this.#pendingClients = result.remaining;
      for (const client of result.matches) {
        this.#removedClients.push(client);
      }
      const isDenied = this.#deniedUsers.has(result.userId);
      if (isDenied) {
        this.#blockedUsers.add(result.userId);
      } else {
        this.#deniedUsers.add(result.userId);
      }
    }
  }

  public dropDemuxId(demuxId: CallingDemuxId): void {
    const activeClients = takeClients(this.#activeClients, demuxId);
    const pendingClients = takeClients(this.#pendingClients, demuxId);
    const removedClients = takeClients(this.#removedClients, demuxId);
    if (activeClients != null) {
      this.#activeClients = activeClients.remaining;
    }
    if (pendingClients != null) {
      this.#pendingClients = pendingClients.remaining;
    }
    if (removedClients != null) {
      this.#removedClients = removedClients.remaining;
    }
  }

  public blockDemuxId(demuxId: CallingDemuxId): void {
    const result = takeClients(this.#activeClients, demuxId);
    if (result != null) {
      this.#activeClients = result.remaining;

      for (const client of result.matches) {
        this.#removedClients.push(client);
      }

      this.#approvedUsers.delete(result.userId);
      this.#blockedUsers.add(result.userId);
    }
  }
}
