// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import assert from 'assert';
import WebSocket from 'ws';
import createDebug from 'debug';

import { signalservice as SignalService } from '../../../protos/compiled';

export type WSRequest = SignalService.WebSocketRequestMessage.Params;
export type WSResponse = SignalService.WebSocketResponseMessage.Params;

const debug = createDebug('mock:ws:service');

const WSMessage = SignalService.WebSocketMessage;

interface RequestOptions {
  readonly body?: Uint8Array;
  readonly headers?: Array<string> | null;
}

export abstract class Service {
  private readonly requests = new Map<bigint, (res: WSResponse) => void>();
  private lastSentId = 0n;

  constructor(protected readonly ws: WebSocket) {
    this.ws = ws;

    // eslint-disable-next-line @typescript-eslint/no-misused-promises
    this.ws.on('message', async (message) => {
      try {
        await this.onMessage(message);
      } catch (error) {
        assert(error instanceof Error);
        debug('onMessage error', error.stack);
      }
    });
    this.ws.once('close', () => this.onClose());
  }

  public async send(
    verb: string,
    path: string,
    options: RequestOptions,
  ): Promise<WSResponse> {
    const id = this.lastSentId++;

    const packet = WSMessage.encode({
      type: WSMessage.Type.REQUEST,
      request: {
        headers: options.headers ?? null,
        body: options.body ?? null,
        verb,
        path,
        id,
      },
      response: null,
    });

    this.ws.send(packet);

    return new Promise((resolve) => this.requests.set(id, resolve));
  }

  private async onMessage(raw: WebSocket.Data): Promise<void> {
    if (!(raw instanceof Uint8Array)) {
      throw new Error('Unexpected input');
    }

    const message = WSMessage.decode(raw);

    if (message.type === WSMessage.Type.RESPONSE) {
      const response = message.response;
      if (!response) {
        throw new Error('Expected response in message');
      }

      const id = response.id ?? 0n;

      const resolve = this.requests.get(id);
      if (!resolve) {
        throw new Error(`Unexpected response: ${id}`);
      }

      resolve(response);
    } else if (message.type === WSMessage.Type.REQUEST) {
      const request = message.request;
      if (!request) {
        throw new Error('Expected request in message');
      }

      let response: WSResponse;
      try {
        response = await this.handleRequest(request);
      } catch (error) {
        assert(error instanceof Error);
        console.error('handleRequest error', error.stack);
        response = {
          id: request.id,
          status: 500,
          message: null,
          headers: null,
          body: Buffer.from(
            JSON.stringify({
              error: error.stack,
            }),
          ),
        };
      }

      // Keepalive responses
      const packet = WSMessage.encode({
        type: WSMessage.Type.RESPONSE,
        request: null,
        response: {
          ...response,
          id: request.id,
        },
      });

      this.ws.send(packet);
    } else {
      debug('unsupported message', message);
    }
  }

  private onClose(): void {
    for (const [id, resolve] of this.requests.entries()) {
      resolve({
        id,
        status: 500,
        message: 'WebSocket is gone',
        headers: null,
        body: null,
      });
    }
  }

  protected abstract handleRequest(request: WSRequest): Promise<WSResponse>;
}
