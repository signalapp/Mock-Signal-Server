// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import createDebug from 'debug';
import { parse as parseURL } from 'url';
import { ParsedUrlQuery, parse as parseQS } from 'querystring';

import { WSRequest, WSResponse } from './service';

import URLPattern from 'url-pattern';

const debug = createDebug('mock:ws:router');

export type AbbreviatedResponse = Readonly<[
  number,
  unknown
]>;

export type Handler = (
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  params: any,
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
      pattern: new URLPattern(pattern),
      handler,
    });
  }

  public get(pattern: string, handler: Handler): void {
    this.register('GET', pattern, handler);
  }

  public put(pattern: string, handler: Handler): void {
    this.register('PUT', pattern, handler);
  }

  public async run(request: WSRequest): Promise<WSResponse> {
    const headers: Record<string, string> = {};
    for (const pair of request.headers ?? []) {
      const [ field, value = '' ] = pair.split(/\s*:\s*/, 2);

      headers[field.toLowerCase()] = value;
    }

    let response: AbbreviatedResponse = [ 404, { error: 'Not found' } ];

    debug(
      'got request %s %s %s',
      this.isAuthenticated ? '(auth)' : '(unauth)',
      request.verb,
      request.path,
    );

    const {
      pathname,
      query,
    } = parseURL(request.path ?? '');

    for (const { method, pattern, handler } of this.routes) {
      if (method !== request.verb) {
        continue;
      }

      const params = pattern.match(pathname ?? '');
      if (!params) {
        continue;
      }

      response = await handler(
        params,
        request.body ?? undefined,
        headers,
        query === null ? undefined : parseQS(query),
      );
      break;
    }

    const [ status, json ] = response;

    debug('response %s %s status=%d', request.verb, request.path, status);

    if (json instanceof Uint8Array) {
      return {
        status,
        headers: [ 'Content-Type:application/x-protobuf' ],
        body: Buffer.from(json),
      };
    }

    return {
      status,
      headers: [ 'Content-Type:application/json' ],
      body: Buffer.from(JSON.stringify(json)),
    };
  }
  public setIsAuthenticated(value: boolean): void {
    this.isAuthenticated = value;
  }
}
