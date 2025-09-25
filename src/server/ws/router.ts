// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import createDebug from 'debug';
import { parse as parseURL } from 'url';
import { ParsedUrlQuery, parse as parseQS } from 'querystring';

import { WSRequest, WSResponse } from './service';

import { JsonValue, PartialDeep } from 'type-fest';
import URLPattern from 'url-pattern';
import { assertJsonValue } from '../../util';
import assert from 'assert';

const debug = createDebug('mock:ws:router');

export type AbbreviatedResponse = Readonly<
  | [number, PartialDeep<JsonValue>]
  | [number, PartialDeep<JsonValue>, Record<string, string>]
>;

export type Handler = (
  params: Record<string, string>,
  body: Uint8Array | undefined,
  headers: Record<string, string>,
  query?: ParsedUrlQuery,
) => Promise<AbbreviatedResponse>;

type Route = Readonly<{
  method: string;
  pattern: URLPattern;
  handler: Handler;
}>;

export class Router {
  private readonly routes: Array<Route> = [];

  private isAuthenticated = false;

  public register(method: string, pattern: string, handler: Handler): void {
    this.routes.push({
      method,
      pattern: new URLPattern(pattern, {
        segmentValueCharset: ':a-zA-Z0-9-_~ %',
      }),
      handler,
    });
  }

  public get(pattern: string, handler: Handler): void {
    this.register('GET', pattern, handler);
  }

  public put(pattern: string, handler: Handler): void {
    this.register('PUT', pattern, handler);
  }

  public post(pattern: string, handler: Handler): void {
    this.register('POST', pattern, handler);
  }

  public del(pattern: string, handler: Handler): void {
    this.register('DELETE', pattern, handler);
  }

  public async run(request: WSRequest): Promise<WSResponse> {
    const headers: Record<string, string> = {};
    for (const pair of request.headers ?? []) {
      const [field, value = ''] = pair.split(/\s*:\s*/, 2);
      assert(field != null, 'Missing field name for header');
      headers[field.toLowerCase()] = value;
    }

    let response: AbbreviatedResponse = [404, { error: 'Not found' }];

    debug(
      'got request %s %s %s',
      this.isAuthenticated ? '(auth)' : '(unauth)',
      request.verb,
      request.path,
    );

    // eslint-disable-next-line @typescript-eslint/no-deprecated
    const { pathname, query } = parseURL(request.path ?? '');

    for (const { method, pattern, handler } of this.routes) {
      if (method !== request.verb) {
        continue;
      }

      const params: unknown = pattern.match(pathname ?? '');
      if (params == null) {
        continue;
      }

      const decodedParams: Record<string, string> = {};
      for (const [key, value] of Object.entries(params)) {
        decodedParams[key] = decodeURIComponent(String(value));
      }

      response = await handler(
        decodedParams,
        request.body ?? undefined,
        headers,
        query === null ? undefined : parseQS(query),
      );
      break;
    }

    const [status, json, responseHeaders = {}] = response;

    debug('response %s %s status=%d', request.verb, request.path, status);

    const timestampHeader = `X-Signal-Timestamp:${Date.now()}`;
    const replyHeaders = [timestampHeader].concat(
      Object.entries(responseHeaders).map(
        ([name, value]) => `${name}:${value}`,
      ),
    );

    if (json instanceof Uint8Array) {
      return {
        status,
        headers: ['Content-Type:application/x-protobuf'].concat(replyHeaders),
        body: Buffer.from(json),
      };
    }

    assertJsonValue(json);
    return {
      status,
      headers: replyHeaders.concat(['Content-Type:application/json']),
      body: Buffer.from(JSON.stringify(json)),
    };
  }
  public setIsAuthenticated(value: boolean): void {
    this.isAuthenticated = value;
  }
}
