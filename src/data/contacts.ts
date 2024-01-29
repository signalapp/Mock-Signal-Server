// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import { AciString } from '../types';

import { signalservice as Proto } from '../../protos/compiled';

export type Contact = Readonly<{
  aci: AciString;
  number: string;
  profileName: string;
}>;

export function serializeContacts(contacts: ReadonlyArray<Contact>): Buffer {
  const chunks = contacts.map((contact) => {
    const { aci, number, profileName: name } = contact;
    return Buffer.from(Proto.ContactDetails.encode({
      aci,
      number,
      name,
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
