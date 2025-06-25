// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import { signalservice as Proto } from '../../protos/compiled';

export type Contact = Readonly<{
  aciBinary: Uint8Array;
  number: string;
  profileName: string;
}>;

export function serializeContacts(contacts: ReadonlyArray<Contact>): Buffer {
  const chunks = contacts
    .map((contact) => {
      const { aciBinary, number, profileName: name } = contact;
      return Buffer.from(
        Proto.ContactDetails.encode({
          aciBinary,
          number,
          name,
        }).finish(),
      );
    })
    .map((chunk) => {
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

      return [Buffer.from(size), chunk];
    });

  return Buffer.concat(chunks.flat());
}
