// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import { UUID } from '../types';

import { signalservice as Proto } from '../../protos/compiled';

export interface Contact {
  readonly uuid: UUID;
  readonly number: string;
  readonly profileName: string;
  readonly profileKey: Buffer;
}

export function serializeContacts(contacts: ReadonlyArray<Contact>): Buffer {
  const chunks = contacts.map((contact) => {
    const { uuid, number, profileName: name, profileKey } = contact;
    return Buffer.from(Proto.ContactDetails.encode({
      uuid,
      number,
      name,
      profileKey,
    }).finish());
  }).map((chunk) => {
    const size: Array<number> = [];

    let remaining = chunk.length;
    do {
      let element = remaining & 0x7f;
      remaining >>>= 7;

      if (remaining !== 0) {
        element |= 0x80;
      }
      size.push(element);
    } while (remaining !== 0);

    return [
      Buffer.from(size),
      chunk,
    ];
  });

  return Buffer.concat(chunks.flat());
}
