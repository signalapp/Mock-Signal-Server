// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import createDebug from 'debug';
import type { ServerRequest, ServerResponse } from 'microrouter';
import { send } from 'micro';
import { ParseAuthHeaderResult, parseAuthHeader } from '../util';
import type { Server } from './base';
import type { Device } from '../data/device';

const debug = createDebug('mock:server:base');

export function parsePassword(req: ServerRequest): ParseAuthHeaderResult {
  return parseAuthHeader(req.headers.authorization);
}

export async function auth(
  server: Server,
  req: ServerRequest,
  res: ServerResponse,
): Promise<Device | undefined> {
  const { username, password, error } = parsePassword(req);
  if (error) {
    debug('%s %s auth failed, error %j', req.method, req.url, error);
    void send(res, 401, { error });
    return;
  }

  const device = await server.auth(username ?? '', password ?? '');
  if (!device) {
    debug('%s %s auth failed, need re-provisioning', req.method, req.url);
    void send(res, 401, { error: 'Need re-provisioning' });
    return;
  }

  return device;
}
