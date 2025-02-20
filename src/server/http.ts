// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import { UuidCiphertext } from '@signalapp/libsignal-client/zkgroup';
import assert from 'assert';
import { Buffer } from 'buffer';
import createDebug from 'debug';
import Long from 'long';
import { RequestHandler, buffer, json, send } from 'micro';
import {
  AugmentedRequestHandler as RouteHandler,
  ServerRequest,
  ServerResponse,
  del,
  get,
  head,
  options,
  patch,
  post,
  put,
  router,
  withNamespace,
} from 'microrouter';
import { type FileHandle, open, readFile, stat } from 'node:fs/promises';
import { pipeline } from 'node:stream/promises';
import { Server as TusServer } from '@tus/server';
import { FileStore } from '@tus/file-store';

import { signalservice as Proto } from '../../protos/compiled';
import { Device } from '../data/device';
import {
  CreateCallLinkSchema,
  DeleteCallLinkSchema,
  PositiveInt,
  UpdateCallLinkSchema,
} from '../data/schemas';
import { AttachmentId } from '../types';
import { ParseAuthHeaderResult, parseAuthHeader } from '../util';
import { CallLinkEntry, Server } from './base';
import { ServerGroup } from './group';
import { join } from 'path';
import { createHash } from 'crypto';

const debug = createDebug('mock:http');

const ALL_METHODS = [get, post, put, patch, del, head, options] as const;

const parsePassword = (req: ServerRequest): ParseAuthHeaderResult => {
  return parseAuthHeader(req.headers.authorization);
};

function getContentType(filePath: string): string {
  const ext = filePath.toLowerCase().split('.').pop();
  switch (ext) {
    case 'json':
      return 'application/json';
    case 'png':
      return 'image/png';
    default:
      return 'application/octet-stream';
  }
}

export const createHandler = (
  server: Server,
  {
    cdn3Path,
    updates2Path,
  }: { cdn3Path: string | undefined; updates2Path: string | undefined },
): RequestHandler => {
  //
  // CDN
  //

  const tusServer = new TusServer({
    path: '/cdn3',
    datastore: new FileStore({ directory: cdn3Path ?? '' }),
    namingFunction: (req) => {
      assert(req.url);
      return req.url.replace(/^(\/cdn3)?\/+/, '');
    },
  });

  const getResourcesAttachment = get('/updates2/*', async (req, res) => {
    const thePath = req.params._;

    assert(
      updates2Path,
      'updates2Path must be provided to retrieve from updates2',
    );

    if (!thePath) {
      send(res, 400, { error: 'Missing path' });
      return;
    }

    let file: FileHandle | undefined;
    try {
      file = await open(join(updates2Path, thePath), 'r');

      const { size, mtime } = await file.stat();
      const etag = `"${mtime.getTime().toString(16)}"`;

      res.writeHead(200, {
        'Content-Length': size,
        'Content-Type': getContentType(thePath),
        ETag: etag,
      });
      await pipeline(file.createReadStream(), res);
    } catch (e) {
      await file?.close();

      assert(e instanceof Error);
      if ('code' in e && e.code === 'ENOENT') {
        return send(res, 404);
      }
      return send(res, 500, e.message);
    }
  });

  const headResourcesAttachment = head('/updates2/*', async (req, res) => {
    const thePath = req.params._;

    assert(
      updates2Path,
      'updates2Path must be provided to retrieve from updates2',
    );

    if (!thePath) {
      send(res, 400, { error: 'Missing path' });
      return;
    }

    const filePath = join(updates2Path, thePath);

    try {
      const { size } = await stat(filePath);
      const fileContent = await readFile(filePath);
      const etag = createHash('md5')
        .update(new Uint8Array(fileContent))
        .digest('hex');

      res.writeHead(200, {
        'Content-Length': size,
        ETag: etag,
      });
      res.end();
    } catch (e) {
      assert(e instanceof Error);
      if ('code' in e && e.code === 'ENOENT') {
        return send(res, 404);
      }
      return send(res, 500, e.message);
    }
  });

  const getCdn3Attachment = get('/cdn3/:folder/*', async (req, res) => {
    assert(cdn3Path, 'cdn3Path must be set');

    if (req.params.folder === 'backups') {
      const { username, password, error } = parsePassword(req);
      if (error) {
        debug(
          '%s %s backup cdn auth failed, error %j',
          req.method,
          req.url,
          error,
        );
        send(res, 401, { error });
        return;
      }
      if (!username || !password) {
        send(res, 401, { error: 'Missing username and/or password' });
        return;
      }
      const authorized = await server.authorizeBackupCDN(username, password);
      if (!authorized) {
        send(res, 403, { error: 'Invalid password' });
        return;
      }
    }

    let file: FileHandle | undefined;
    try {
      file = await open(join(cdn3Path, req.params.folder, req.params._), 'r');

      const { size } = await file.stat();

      res.writeHead(200, {
        'Content-Length': size,
      });
      await pipeline(file.createReadStream(), res);
    } catch (e) {
      await file?.close();

      assert(e instanceof Error);
      if ('code' in e && e.code === 'ENOENT') {
        return send(res, 404);
      }
      return send(res, 500, e.message);
    }
  });

  const getAttachment = get('/attachments/:key', async (req, res) => {
    // TODO(indutny): range requests
    const { key } = req.params;
    const result = await server.fetchAttachment(key as AttachmentId);
    if (!result) {
      return send(res, 404, { error: 'Attachment not found' });
    }
    return result;
  });

  const getStickerPack = get(
    '/stickers/:pack/manifest.proto',
    async (req, res) => {
      const { pack } = req.params;
      const result = await server.fetchStickerPack(pack);
      if (!result) {
        return send(res, 404, { error: 'Sticker pack not found' });
      }
      return result;
    },
  );

  const getSticker = get('/stickers/:pack/full/:sticker', async (req, res) => {
    const { pack, sticker } = req.params;
    const result = await server.fetchSticker(pack, parseInt(sticker, 10));
    if (!result) {
      return send(res, 404, { error: 'Sticker not found' });
    }
    return result;
  });

  const notFound: RouteHandler = async (req, res) => {
    debug('Unsupported request %s %s', req.method, req.url);
    return send(res, 404, { error: 'Not supported yet' });
  };

  //
  // Calling
  //

  function toCallLinkResponse(callLink: CallLinkEntry) {
    return {
      name: callLink.encryptedName,
      restrictions: String(callLink.restrictions),
      revoked: callLink.revoked,
      expiration: Math.floor(callLink.expiration / 1000), // unix
    };
  }

  const getCallLink = get('/v1/call-link/', async (req, res) => {
    const roomId = req.headers['x-room-id'];
    if (typeof roomId !== 'string') {
      return send(res, 400, { error: 'Missing room ID' });
    }

    const callLink = await server.getCallLink(roomId);
    if (!callLink) {
      return send(res, 404, { error: 'Call link not found' });
    }

    return toCallLinkResponse(callLink);
  });

  const createOrUpdateCallLink = put('/v1/call-link', async (req, res) => {
    const roomId = req.headers['x-room-id'];
    if (typeof roomId !== 'string') {
      return send(res, 400, { error: 'Missing room ID' });
    }

    const body = await json(req);

    let callLink: CallLinkEntry;
    if (!server.hasCallLink(roomId)) {
      const createParams = CreateCallLinkSchema.parse(body);
      callLink = await server.createCallLink(roomId, createParams);
    } else {
      const updateParams = UpdateCallLinkSchema.parse(body);
      callLink = await server.updateCallLink(roomId, updateParams);
    }

    return toCallLinkResponse(callLink);
  });

  const deleteCallLink = del('/v1/call-link', async (req, res) => {
    const roomId = req.headers['x-room-id'];
    if (typeof roomId !== 'string') {
      return send(res, 400, { error: 'Missing room ID' });
    }
    const deleteParams = DeleteCallLinkSchema.parse(await json(req));
    await server.deleteCallLink(roomId, deleteParams);
    return {};
  });

  //
  // Authorized requests
  //

  async function auth(
    req: ServerRequest,
    res: ServerResponse,
  ): Promise<Device | undefined> {
    const { username, password, error } = parsePassword(req);
    if (error) {
      debug('%s %s auth failed, error %j', req.method, req.url, error);
      send(res, 401, { error });
      return;
    }

    const device = await server.auth(username ?? '', password ?? '');
    if (!device) {
      debug('%s %s auth failed, need re-provisioning', req.method, req.url);
      send(res, 401, { error: 'Need re-provisioning' });
      return;
    }

    return device;
  }

  type GroupAuthResult = Readonly<{
    publicParams: Buffer;
    aciCiphertext: UuidCiphertext;
    pniCiphertext: UuidCiphertext;
  }>;

  async function groupAuth(
    req: ServerRequest,
    res: ServerResponse,
  ): Promise<GroupAuthResult | undefined> {
    const { error, username, password } = parsePassword(req);

    if (error) {
      send(res, 400, { error });
      return undefined;
    }
    if (!username || !password) {
      send(res, 400, { error: 'Invalid authorization header' });
      return undefined;
    }

    const publicParams = Buffer.from(username, 'hex');
    const credential = Buffer.from(password, 'hex');

    let aciCiphertext: UuidCiphertext;
    let pniCiphertext: UuidCiphertext;
    try {
      const auth = await server.verifyGroupCredentials(
        publicParams,
        credential,
      );

      aciCiphertext = auth.getUuidCiphertext();
      const maybePni = auth.getPniCiphertext();
      assert(maybePni, 'Auth credentials must have PNI');
      pniCiphertext = maybePni;
    } catch (_) {
      send(res, 403, { error: 'Invalid credentials' });
      return undefined;
    }

    return { publicParams, aciCiphertext, pniCiphertext };
  }

  type GroupAuthAndFetchResult = Readonly<{
    group: ServerGroup;
    aciCiphertext: UuidCiphertext;
    pniCiphertext: UuidCiphertext;
  }>;

  async function groupAuthAndFetch(
    req: ServerRequest,
    res: ServerResponse,
  ): Promise<GroupAuthAndFetchResult | undefined> {
    const auth = await groupAuth(req, res);
    if (!auth) {
      return;
    }

    const group = await server.getGroup(auth.publicParams);
    if (!group) {
      send(res, 404, { error: 'Group not found' });
      return undefined;
    }

    return { group, ...auth };
  }

  async function storageAuth(
    req: ServerRequest,
    res: ServerResponse,
  ): Promise<Device | undefined> {
    const { error, username, password } = parsePassword(req);

    if (error) {
      send(res, 400, { error });
      return undefined;
    }
    if (!username || !password) {
      send(res, 400, { error: 'Invalid authorization header' });
      return undefined;
    }

    const device = await server.storageAuth(username, password);
    if (!device) {
      debug('%s %s storage auth failed', req.method, req.url);
      send(res, 403, { error: 'Invalid authorization' });
      return undefined;
    }

    return device;
  }

  //
  // GV2
  //

  const getGroupV1 = get('/v1/groups', async (req, res) => {
    const auth = await groupAuthAndFetch(req, res);
    if (!auth) {
      return;
    }
    const { group } = auth;
    return send(res, 200, Proto.Group.encode(group.state).finish());
  });

  const getGroup = get('/v2/groups', async (req, res) => {
    const auth = await groupAuthAndFetch(req, res);
    if (!auth) {
      return;
    }
    const { group } = auth;
    const groupSendEndorsementResponse = group.getGroupSendEndorsementResponse(
      auth.aciCiphertext,
    );
    return send(
      res,
      200,
      Proto.GroupResponse.encode({
        group: group.state,
        groupSendEndorsementResponse,
      }).finish(),
    );
  });

  const getGroupVersion = get(
    '/v1/groups/joined_at_version',
    async (req, res) => {
      const auth = await groupAuthAndFetch(req, res);
      if (!auth) {
        return;
      }

      const { group, aciCiphertext } = auth;

      const member = group.getMember(aciCiphertext);

      if (!member) {
        return send(res, 403, { error: 'Not a member of this group' });
      }

      return send(
        res,
        200,
        Proto.Member.encode({
          joinedAtVersion: member.joinedAtVersion,
        }).finish(),
      );
    },
  );

  const SECONDS_IN_SIX_HOURS = 6 * 60 * 60;

  async function getGroupLogsInner(
    req: ServerRequest,
    res: ServerResponse,
  ): Promise<{
    auth: GroupAuthAndFetchResult;
    groupChanges: Proto.IGroupChanges;
  } | void> {
    const auth = await groupAuthAndFetch(req, res);
    if (!auth) {
      return;
    }

    const { group, aciCiphertext } = auth;
    const member = group.getMember(aciCiphertext);
    if (!member) {
      return send(res, 403, { error: 'Not a member of this group' });
    }

    const since = parseInt(req.params.since, 10);
    if (since < (member.joinedAtVersion ?? 0)) {
      return send(res, 403, { error: '`since` is before joinedAtVersion' });
    }

    return {
      auth,
      groupChanges: group.getChangesSince(since),
    };
  }

  const getGroupLogsV1 = get('/v1/groups/logs/:since', async (req, res) => {
    const result = await getGroupLogsInner(req, res);
    if (!result) {
      return;
    }
    return send(
      res,
      200,
      Proto.GroupChanges.encode({
        groupChanges: result.groupChanges.groupChanges,
      }).finish(),
    );
  });

  const getGroupLogs = get('/v2/groups/logs/:since', async (req, res) => {
    const result = await getGroupLogsInner(req, res);
    if (!result) {
      return;
    }

    const {
      groupChanges: { groupChanges },
      auth,
    } = result;
    const { group } = auth;

    const expirationResult = PositiveInt.safeParse(
      req.headers['cached-send-endorsements'],
    );

    if (!expirationResult.success) {
      return send(res, 400);
    }

    const expirationTime = expirationResult.data;
    const currentTime = Math.floor(Date.now() / 1000);
    const expiresInLessThanSixHours =
      expirationTime < currentTime + SECONDS_IN_SIX_HOURS;

    const membershipChange = groupChanges?.find((change) => {
      const encodedActions = change.groupChange?.actions;
      if (!encodedActions) {
        return false;
      }
      const actions = Proto.GroupChange.Actions.decode(encodedActions);
      return (
        actions.addMembers.length > 0 ||
        actions.deleteMembers.length > 0 ||
        actions.promoteMembersPendingPniAciProfileKey.length > 0 ||
        actions.promotePendingMembers.length > 0
      );
    });

    let groupSendEndorsementResponse: Uint8Array | null = null;

    if (membershipChange || expiresInLessThanSixHours) {
      groupSendEndorsementResponse = group.getGroupSendEndorsementResponse(
        auth.aciCiphertext,
      );
    }

    return send(
      res,
      200,
      Proto.GroupChanges.encode({
        groupChanges,
        groupSendEndorsementResponse,
      }).finish(),
    );
  });

  async function createGroupInner(
    req: ServerRequest,
    res: ServerResponse,
  ): Promise<{ auth: GroupAuthResult; group: ServerGroup } | void> {
    const auth = await groupAuth(req, res);
    if (!auth) {
      return;
    }

    const groupData = Proto.Group.decode(Buffer.from(await buffer(req)));
    if (!groupData.title) {
      return send(res, 400, { error: 'Missing group title' });
    }
    if (
      !groupData.publicKey ||
      !auth.publicParams.equals(groupData.publicKey)
    ) {
      return send(res, 400, { error: 'Invalid group public key' });
    }

    const group = await server.createGroup(groupData);

    // TODO(indutny): verify that creator is a member

    return { auth, group };
  }

  const createGroupV1 = put('/v1/groups', async (req, res) => {
    const result = await createGroupInner(req, res);
    if (!result) {
      return;
    }
    return send(res, 200);
  });

  const createGroup = put('/v2/groups', async (req, res) => {
    const result = await createGroupInner(req, res);
    if (!result) {
      return;
    }
    const { group, auth } = result;
    return send(
      res,
      200,
      Proto.GroupResponse.encode({
        group: group.state,
        groupSendEndorsementResponse: group.getGroupSendEndorsementResponse(
          auth.aciCiphertext,
        ),
      }).finish(),
    );
  });

  async function modifyGroupInner(
    req: ServerRequest,
    res: ServerResponse,
  ): Promise<{
    auth: GroupAuthAndFetchResult;
    signedChange: Proto.IGroupChange;
  } | void> {
    const auth = await groupAuthAndFetch(req, res);
    if (!auth) {
      return;
    }

    const actions = Proto.GroupChange.Actions.decode(
      Buffer.from(await buffer(req)),
    );

    if (actions.groupId.length) {
      return send(res, 400, { error: 'Bad Request' });
    }

    const { group, aciCiphertext, pniCiphertext } = auth;

    try {
      const modifyResult = await server.modifyGroup({
        group,
        aciCiphertext: aciCiphertext.serialize(),
        pniCiphertext: pniCiphertext.serialize(),
        actions,
      });

      if (modifyResult.conflict) {
        return send(res, 409, { error: 'Conflict' });
      }

      return {
        auth,
        signedChange: modifyResult.signedChange,
      };
    } catch (error) {
      assert(error instanceof Error);

      debug('Failed to modify group', error.stack);

      // TODO(indutny): would be nice to give 403 here
      return send(res, 500, { error: error.stack });
    }
  }

  const modifyGroupV1 = patch('/v1/groups', async (req, res) => {
    const result = await modifyGroupInner(req, res);
    if (!result) {
      return;
    }
    const { signedChange } = result;
    return send(res, 200, Proto.GroupChange.encode(signedChange).finish());
  });

  const modifyGroup = patch('/v2/groups', async (req, res) => {
    const result = await modifyGroupInner(req, res);
    if (!result) {
      return;
    }
    const { signedChange, auth } = result;
    const { group, aciCiphertext } = auth;
    return send(
      res,
      200,
      Proto.GroupChangeResponse.encode({
        groupChange: signedChange,
        groupSendEndorsementResponse:
          group.getGroupSendEndorsementResponse(aciCiphertext),
      }).finish(),
    );
  });

  //
  // Storage Service
  //

  const getStorageManifest = get('/v1/storage/manifest', async (req, res) => {
    const device = await storageAuth(req, res);
    if (!device) {
      return;
    }

    const manifest = await server.getStorageManifest(device);
    if (!manifest) {
      return send(res, 404, { error: 'Manifest not found' });
    }

    return send(res, 200, Proto.StorageManifest.encode(manifest).finish());
  });

  const getStorageManifestByVersion = get(
    '/v1/storage/manifest/version/:after',
    async (req, res) => {
      const device = await storageAuth(req, res);
      if (!device) {
        return;
      }

      const after = Long.fromString(req.params.after);
      const manifest = await server.getStorageManifest(device);
      if (!manifest?.version?.gt(after)) {
        return send(res, 204);
      }

      return send(res, 200, Proto.StorageManifest.encode(manifest).finish());
    },
  );

  const putStorage = put('/v1/storage/', async (req, res) => {
    const device = await storageAuth(req, res);
    if (!device) {
      return;
    }

    const writeOperation = Proto.WriteOperation.decode(
      Buffer.from(await buffer(req)),
    );

    const result = await server.applyStorageWrite(device, writeOperation);
    if ('error' in result) {
      return send(res, 400, { error: result.error });
    }

    if (!result.updated) {
      return send(
        res,
        409,
        Proto.StorageManifest.encode(result.manifest).finish(),
      );
    }

    return send(res, 200);
  });

  const putStorageRead = put('/v1/storage/read', async (req, res) => {
    const device = await storageAuth(req, res);
    if (!device) {
      return;
    }

    const readOperation = Proto.ReadOperation.decode(
      Buffer.from(await buffer(req)),
    );

    const keys = (readOperation.readKey || []).map((key) => Buffer.from(key));

    const items = await server.getStorageItems(device, keys);
    if (!items) {
      return send(res, 413, { error: 'Requested too many items' });
    }

    return send(
      res,
      200,
      Proto.StorageItems.encode({
        items,
      }).finish(),
    );
  });

  const notFoundAfterAuth: RouteHandler = async (req, res) => {
    const device = await auth(req, res);
    if (!device) {
      return;
    }

    debug('Unsupported request %s %s', req.method, req.url);
    return send(res, 404, { error: 'Not supported yet' });
  };

  const routes = router(
    getAttachment,
    getStickerPack,
    getSticker,

    // Technically these should live on a separate server, but who cares
    withNamespace('/storageService')(
      // All storage service routes have the X-Signal-Timestamp header
      ...ALL_METHODS.map((method) =>
        method('/*', (req, res) => {
          res.setHeader('X-Signal-Timestamp', Date.now());
        }),
      ),
      getGroupV1,
      getGroup,
      getGroupVersion,
      getGroupLogsV1,
      getGroupLogs,
      createGroupV1,
      createGroup,
      modifyGroupV1,
      modifyGroup,

      // TODO(indutny): support this
      get('/v1/groups/token', notFound),

      getStorageManifest,
      getStorageManifestByVersion,
      putStorage,
      putStorageRead,
    ),

    getCallLink,
    createOrUpdateCallLink,
    deleteCallLink,

    ...[head, patch, post].map((method) =>
      method('/cdn3/*', async (req, res) => {
        await tusServer.handle(req, res);
      }),
    ),

    getCdn3Attachment,
    getResourcesAttachment,
    headResourcesAttachment,

    get('/stickers/', notFound),
    ...ALL_METHODS.map((method) => method('/*', notFoundAfterAuth)),
  );

  return (req, res) => {
    debug('got request %s %s', req.method, req.url);
    try {
      res.once('finish', () => {
        debug('response %s %s', req.method, req.url, res.statusCode);
      });
      return routes(req, res);
    } catch (error) {
      assert(error instanceof Error);
      debug('request failure %s %s', req.method, req.url, error.stack);
      return send(res, 500, error.message);
    }
  };
};
