// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import { signalservice as Proto } from '../../protos/compiled';

export type Attachment = {
  key: Buffer<ArrayBuffer>;
  blob: Buffer<ArrayBuffer>;
  digest: Buffer<ArrayBuffer>;
  size: number;
};

export function attachmentToPointer(
  cdnKey: string,
  attachment: Attachment,
): Proto.AttachmentPointer.Params {
  return {
    contentType: 'application/octet-stream',
    attachmentIdentifier: {
      cdnKey,
    },
    key: attachment.key,
    size: attachment.size,
    digest: attachment.digest,

    clientUuid: null,
    thumbnail: null,
    incrementalMac: null,
    chunkSize: null,
    fileName: null,
    flags: null,
    width: null,
    height: null,
    caption: null,
    blurHash: null,
    uploadTimestamp: null,
    cdnNumber: null,
  };
}
