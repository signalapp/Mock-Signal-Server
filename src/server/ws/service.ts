// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import assert from 'assert';
import Long from 'long';
import WebSocket from 'ws';
import createDebug from 'debug';

import { signalservice as SignalService } from '../../../protos/compiled';

export type WSRequest = SignalService.IWebSocketRequestMessage;
export type WSResponse = SignalService.IWebSocketResponseMessage;

const debug = createDebug('mock:ws:service');

const WSMessage = SignalService.WebSocketMessage;

interface RequestOptions {
  readonly body?: Uint8Array;
  readonly headers?: Array<string> | null;
}

export abstract class Service {
  private readonly requests: Map<number, (res: WSResponse) => void> = new Map();
  private lastSentId = 0;

  constructor(protected readonly ws: WebSocket) {
    this.ws = ws;

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
        ...options,
        verb,
        path,
        id: Long.fromNumber(id),
      },
    }).finish();

    this.ws.send(packet);

    return await new Promise((resolve) => this.requests.set(id, resolve));
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

      if (!response.id) {
        throw new Error('Expected response.id');
      }

      const id = parseInt(response.id.toString(), 10);
      if (isNaN(id)) {
        throw new Error(`Invalid response.id: ${response.id}`);
      }

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

      if (!request.id) {
        throw new Error('Expected request.id');
      }

      let response: WSResponse;
      try {
        response = await this.handleRequest(request);
      } catch (error) {
        assert(error instanceof Error);
        console.error('handleRequest error', error.stack);
        response = {
          status: 500,
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
        response: {
          ...response,
          id: request.id,
        },
      }).finish();

      this.ws.send(packet);
    } else {
      debug('unsupported message', message);
    }
  }

  private onClose(): void {
    for (const [id, resolve] of this.requests.entries()) {
      resolve({
        id: Long.fromNumber(id),
        status: 500,
        message: 'WebSocket is gone',
      });
    }
  }

  protected abstract handleRequest(request: WSRequest): Promise<WSResponse>;
}
