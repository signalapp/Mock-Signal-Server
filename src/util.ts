// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import assert from 'assert';
import { ProtocolAddress, ServiceId } from '@signalapp/libsignal-client';
import { BufferReader } from 'protobufjs';

import { DAY_IN_SECONDS } from './constants';
import type { DeviceId, RegistrationId, ServiceIdString } from './types';

type PromiseQueueEntry<T> = Readonly<{
  value: T;
  resolvePush?: () => void;
}>;

export type PromiseQueueConfig = Readonly<{
  timeout?: number;
}>;

export type MultiRecipientDestination = Readonly<{
  deviceId: DeviceId;
  registrationId: RegistrationId;
}>;

export type MultiRecipientMessageRecipient = Readonly<{
  serviceId: ServiceIdString;
  destinations: ReadonlyArray<MultiRecipientDestination>;
  material: Buffer;
}>;

export type MultiRecipientMessage = Readonly<{
  recipients: ReadonlyArray<MultiRecipientMessageRecipient>;
  commonMaterial: Buffer;
}>;

export function generateRandomE164(): string {
  // Generate random number
  let number = '+141549';
  for (let i = 0; i < 5; i++) {
    number += Math.floor(Math.random() * 10).toString();
  }
  return number;
}

export type ParseAuthHeaderResult = {
  username: string;
  password: string;
  error?: undefined;
} | {
  username?: undefined
  password?: undefined;
  error: string;
};

const MULTI_RECIPIENT_MESSAGE_VERSION = 0x23;
const MULTI_RECIPIENT_SERVICE_ID_LEN = 17;
const MULTI_RECIPIENT_SHARED_MATERIAL_LEN = 48;

export function parseAuthHeader(header?: string): ParseAuthHeaderResult {
  if (!header) {
    return { error: 'Missing Authorization header' };
  }

  const [ basic, base64 ] = header.split(/\s+/g, 2);
  if (basic.toLowerCase() !== 'basic') {
    return { error: `Unsupported authorization type ${basic}` };
  }

  let username: string;
  let password: string;
  try {
    const decoded = Buffer.from(base64, 'base64').toString();
    [ username, password ] = decoded.split(':', 2);
  } catch (error) {
    assert(error instanceof Error);
    return { error: error.message };
  }

  if (!username) {
    return { error: 'Missing username' };
  }

  if (!password) {
    return { error: 'Missing password' };
  }

  return { username, password };
}

export class PromiseQueue<T> {
  private readonly defaultTimeout: number | undefined;
  private readonly entries: Array<PromiseQueueEntry<T>> = [];
  private readonly resolvers: Array<(value: T) => void> = [];

  constructor(config: PromiseQueueConfig = {}) {
    this.defaultTimeout = config.timeout;
  }

  public async pushAndWait(
    value: T,
    timeout: number | undefined = this.defaultTimeout,
  ): Promise<void> {
    // We were waiting for `.shift()` already
    const resolveEntry = this.resolvers.shift();
    if (resolveEntry) {
      resolveEntry(value);
      return;
    }

    // Not waiting for `.shift()` - queue.
    return await new Promise((resolve, reject) => {
      let timer: NodeJS.Timeout | undefined;

      const entry = {
        value,
        resolvePush() {
          if (timer !== undefined) {
            clearTimeout(timer);
          }
          timer = undefined;

          resolve();
        },
      };

      const cancel = () => {
        const index = this.entries.indexOf(entry);
        if (index === -1) {
          throw new Error('PromiseQueue entries bookkeeping error');
        }
        this.entries.splice(index, 1);

        reject(new Error('PromiseQueue pushAndWait timeout'));
      };

      if (timeout !== undefined) {
        timer = setTimeout(cancel, timeout);
      }

      this.entries.push(entry);
    });
  }

  public push(
    value: T,
  ): void {
    // We were waiting for `.shift()` already
    const resolveEntry = this.resolvers.shift();
    if (resolveEntry) {
      resolveEntry(value);
      return;
    }

    this.entries.push({ value });
  }

  public async shift(
    timeout: number | undefined = this.defaultTimeout,
  ): Promise<T> {
    // `.pushAndWait()` was called before us
    const entry = this.entries.shift();
    if (entry) {
      if (entry.resolvePush) {
        entry.resolvePush();
      }
      return entry.value;
    }

    return await new Promise((resolve, reject) => {
      let timer: NodeJS.Timeout | undefined;

      const resolveEntry = (value: T) => {
        if (timer !== undefined) {
          clearTimeout(timer);
        }
        timer = undefined;

        resolve(value);
      };

      const cancel = () => {
        const index = this.resolvers.indexOf(resolveEntry);
        if (index === -1) {
          throw new Error('PromiseQueue resolvers bookkeeping error');
        }
        this.resolvers.splice(index, 1);

        reject(new Error('PromiseQueue shift timeout'));
      };

      if (timeout !== undefined) {
        timer = setTimeout(cancel, timeout);
      }

      this.resolvers.push(resolveEntry);
    });
  }
}

export function addressToString(address: ProtocolAddress): string {
  return `${address.name()}.${address.deviceId()}`;
}

export function parseMultiRecipientMessage(
  message: Buffer,
): MultiRecipientMessage {
  if (message[0] !== MULTI_RECIPIENT_MESSAGE_VERSION) {
    throw new Error('Invalid multi-recipient message');
  }

  const reader = new BufferReader(message);
  // Version
  reader.skip(1);

  const count = reader.uint32();
  const recipients = new Array<MultiRecipientMessageRecipient>();
  while (recipients.length < count) {
    const serviceId = ServiceId.parseFromServiceIdFixedWidthBinary(
      message.slice(
        reader.pos,
        reader.pos + MULTI_RECIPIENT_SERVICE_ID_LEN,
      ),
    ).getServiceIdString() as ServiceIdString;
    reader.skip(MULTI_RECIPIENT_SERVICE_ID_LEN);

    const destinations = new Array<MultiRecipientDestination>();
    while (reader.pos + 3 <= reader.len) {
      const deviceId = reader.uint32() as DeviceId;
      const registrationIdAndFlag = message.readUInt16BE(reader.pos);
      reader.skip(2);

      const registrationId = (registrationIdAndFlag & 0x7fff) as RegistrationId;

      destinations.push({ deviceId, registrationId });

      if ((registrationIdAndFlag & 0x8000) === 0) {
        break;
      }
    }

    const material = message.slice(
      reader.pos,
      reader.pos + MULTI_RECIPIENT_SHARED_MATERIAL_LEN,
    );
    assert.strictEqual(material.length, MULTI_RECIPIENT_SHARED_MATERIAL_LEN);

    reader.skip(MULTI_RECIPIENT_SHARED_MATERIAL_LEN);

    recipients.push({ serviceId, destinations, material });
  }

  const commonMaterial = message.slice(reader.pos);

  return { recipients, commonMaterial };
}

export function combineMultiRecipientMessage({ material, commonMaterial }: {
  material: Buffer;
  commonMaterial: Buffer;
}): Buffer {
  return Buffer.concat([
    Buffer.from([ MULTI_RECIPIENT_MESSAGE_VERSION ]),
    material,
    commonMaterial,
  ]);
}

export function getTodayInSeconds(): number {
  const now = Date.now() / 1000;

  return now - (now % DAY_IN_SECONDS);
}

export function generateRegistrationId(): RegistrationId {
  return Math.max(1, (Math.random() * 0x4000) | 0) as RegistrationId;
}

export function toURLSafeBase64(buf: Uint8Array): string {
  return Buffer.from(buf)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

export function fromURLSafeBase64(base64: string): Buffer {
  const source = base64.replace(/-/g, '+').replace(/_/g, '/');

  // Note that `Buffer.from()` ignores padding anyway so we don't need to
  // restore it.
  return Buffer.from(source, 'base64');
}
