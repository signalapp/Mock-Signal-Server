// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import assert from 'node:assert';
import { randomBytes } from 'node:crypto';
import z from 'zod';

function getRandomBase64String(size: number): string {
  assert(size % 4 === 0, 'Must be multiple of 4');
  const byteLength = (size * 6) / 8;
  const bytes = randomBytes(byteLength);
  const base64 = bytes.toString('base64');
  assert(base64.length === size, 'Must be exact length');
  return base64;
}

export type IceUsernameFragment = string & {
  IceUsernameFragment: never;
};

export const ICE_USERNAME_FRAGMENT_SIZE = 4;

export function getRandomIceUsernameFragment(): IceUsernameFragment {
  return getRandomBase64String(
    ICE_USERNAME_FRAGMENT_SIZE,
  ) as IceUsernameFragment;
}

export const IceUsernameFragmentSchema = z
  .string()
  .min(4)
  .max(256)
  .transform((input) => input as IceUsernameFragment);

export type IceUsername = `${IceUsernameFragment}:${IceUsernameFragment}` & {
  IceUsername: never;
};

export type IceUsernamesParams = Readonly<{
  serverIceUsernameFragment: IceUsernameFragment;
  clientIceUsernameFragment: IceUsernameFragment;
}>;

export type IceUsernames = Readonly<{
  serverIceUsername: IceUsername;
  clientIceUsername: IceUsername;
}>;

function toIceUsername(
  a: IceUsernameFragment,
  b: IceUsernameFragment,
): IceUsername {
  return `${a}:${b}` as IceUsername;
}

export function getIceUsernames(params: IceUsernamesParams): IceUsernames {
  const serverIceUsername = toIceUsername(
    params.serverIceUsernameFragment,
    params.clientIceUsernameFragment,
  );
  const clientIceUsername = toIceUsername(
    params.clientIceUsernameFragment,
    params.serverIceUsernameFragment,
  );
  return { serverIceUsername, clientIceUsername };
}

export function getClientIceUsername(params: {
  serverIceUsernameFragment: IceUsernameFragment;
  clientIceUsernameFragment: IceUsernameFragment;
}): IceUsername {
  return `${params.clientIceUsernameFragment}:${params.serverIceUsernameFragment}` as IceUsername;
}

export type IcePassword = string & { IcePassword: never };

export const ICE_PASSWORD_SIZE = 32;

export function getRandomIcePassword(): IcePassword {
  return getRandomBase64String(ICE_PASSWORD_SIZE) as IcePassword;
}

export const IcePasswordSchema = z
  .string()
  .min(22)
  .max(256)
  .transform((input) => input as IcePassword);
