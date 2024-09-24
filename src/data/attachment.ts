// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import { signalservice as Proto } from '../../protos/compiled';

export type Attachment = {
  key: Buffer;
  blob: Buffer;
  digest: Buffer;
  size: number;
};

export function attachmentToPointer(
  cdnKey: string,
  attachment: Attachment,
): Proto.IAttachmentPointer {
  return {
    contentType: 'application/octet-stream',
    cdnKey,
    key: attachment.key,
    size: attachment.size,
    digest: attachment.digest,
  };
}
