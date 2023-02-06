// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import assert from 'assert';
import Long from 'long';
import { Buffer } from 'buffer';
import { RequestHandler, buffer, json, send } from 'micro';
import {
  AugmentedRequestHandler as RouteHandler,
  ServerRequest,
  ServerResponse,
  del,
  get,
  patch,
  put,
  router,
} from 'microrouter';
import { PublicKey } from '@signalapp/libsignal-client';
import type { UuidCiphertext } from '@signalapp/libsignal-client/zkgroup';
import createDebug from 'debug';

import { Server } from './base';
import { ServerGroup } from './group';
import { Device } from '../data/device';
import {
  ParseAuthHeaderResult,
  fromURLSafeBase64,
  parseAuthHeader,
  toURLSafeBase64,
} from '../util';
import {
  DeviceKeysSchema,
  RegistrationDataSchema,
  UsernameConfirmationSchema,
  UsernameReservationSchema,
} from '../data/schemas';
import { UUIDKind } from '../types';
import { signalservice as Proto } from '../../protos/compiled';

const debug = createDebug('mock:http');

const parsePassword = (req: ServerRequest): ParseAuthHeaderResult => {
  return parseAuthHeader(req.headers.authorization);
};

const sendDevicesKeys = async (
  res: ServerResponse,
  uuidKind: UUIDKind,
  devices: ReadonlyArray<Device>,
): Promise<void> => {
  const [ primary ] = devices;
  assert(primary !== undefined, 'Empty device list');

  const identityKey = await primary.getIdentityKey(uuidKind);

  send(res, 200, {
    identityKey: identityKey.serialize().toString('base64'),
    devices: await Promise.all(devices.map(async (device) => {
      const { signedPreKey, preKey } =
        await device.popSingleUseKey(uuidKind);
      return {
        deviceId: device.deviceId,
        registrationId: device.getRegistrationId(uuidKind),
        signedPreKey: {
          keyId: signedPreKey.keyId,
          publicKey: signedPreKey.publicKey.serialize().toString('base64'),
          signature: signedPreKey.signature.toString('base64'),
        },
        preKey: preKey && {
          keyId: preKey.keyId,
          publicKey: preKey.publicKey.serialize().toString('base64'),
        },
      };
    })),
  });
};

export const createHandler = (server: Server): RequestHandler => {
  //
  // Unauthorized requests
  //

  const provisionDevice = put('/v1/devices/:code', async (req, res) => {
    const { error, username, password } = parsePassword(req);
    if (error) {
      return send(res, 400, { error });
    }
    if (!username || !password) {
      return send(res, 400, { error: 'Invalid authorization header' });
    }

    const body = RegistrationDataSchema.parse(await json(req));

    const device = await server.provisionDevice({
      number: username,
      password,
      provisioningCode: req.params.code as string,
      registrationId: body.registrationId as number,
      pniRegistrationId: body.pniRegistrationId as number,
    });

    return { deviceId: device.deviceId, uuid: device.uuid, pni: device.pni };
  });

  // TODO(indutny): add a route for /v2/keys/:uuid
  const getDeviceKeys = get('/v2/keys/:uuid/:deviceId', async (req, res) => {
    const uuid = req.params.uuid;
    const deviceId = parseInt(req.params.deviceId || '', 10);
    if (!uuid || deviceId.toString() !== req.params.deviceId) {
      return send(res, 400, { error: 'Invalid request parameters' });
    }

    const device = await server.getDeviceByUUID(uuid, deviceId);
    if (!device) {
      return send(res, 404, { error: 'Device not found' });
    }

    const uuidKind = device.getUUIDKind(uuid);
    return await sendDevicesKeys(res, uuidKind, [ device ]);
  });

  const getAllDeviceKeys = get('/v2/keys/:uuid(/\\*)', async (req, res) => {
    const uuid = req.params.uuid;
    if (!uuid) {
      return send(res, 400, { error: 'Invalid request parameters' });
    }

    const devices = await server.getAllDevicesByUUID(uuid);
    if (devices.length === 0) {
      return send(res, 404, { error: 'Account not found' });
    }

    const uuidKind = devices[0].getUUIDKind(uuid);
    return await sendDevicesKeys(res, uuidKind, devices);
  });

  //
  // CDN
  //

  const getAttachment = get('/attachments/:key/:subkey', async (req, res) => {
    const { key, subkey } = req.params;
    const result = await server.fetchAttachment(`${key}/${subkey}`);
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

  function uuidKindFromQuery(req: ServerRequest): UUIDKind {
    if (req.query.identity === 'pni') {
      return UUIDKind.PNI;
    }
    return UUIDKind.ACI;
  }

  const putKeys = put('/v2/keys', async (req, res) => {
    const device = await auth(req, res);
    if (!device) {
      return;
    }

    const uuidKind = uuidKindFromQuery(req);

    const body = DeviceKeysSchema.parse(await json(req));
    try {
      const parseKey = (base64: string): PublicKey => {
        return PublicKey.deserialize(Buffer.from(base64, 'base64'));
      };

      await server.updateDeviceKeys(device, uuidKind, {
        identityKey: parseKey(body.identityKey),
        signedPreKey: {
          keyId: body.signedPreKey.keyId,
          publicKey: parseKey(body.signedPreKey.publicKey),
          signature: Buffer.from(body.signedPreKey.signature, 'base64'),
        },
        preKeys: body.preKeys.map((preKey) => {
          return {
            keyId: preKey.keyId,
            publicKey: parseKey(preKey.publicKey),
          };
        }),
      });
    } catch (error) {
      assert(error instanceof Error);
      debug('updateDeviceKeys error', error.stack);
      return send(res, 400, { error: error.message });
    }

    return { ok: true };
  });

  const getKeys = get('/v2/keys', async (req, res) => {
    const device = await auth(req, res);
    if (!device) {
      return;
    }

    const uuidKind = uuidKindFromQuery(req);

    return { count: await device.getSingleUseKeyCount(uuidKind) };
  });

  const whoami = get('/v1/accounts/whoami', async (req, res) => {
    const device = await auth(req, res);
    if (!device) {
      return;
    }

    return { uuid: device.uuid, pni: device.pni, number: device.number };
  });

  const reserveUsername = put(
    '/v1/accounts/username_hash/reserve',
    async (req, res) => {
      const device = await auth(req, res);
      if (!device) {
        return;
      }

      const body = UsernameReservationSchema.parse(await json(req));

      const usernameHash = await server.reserveUsername(device.uuid, body);

      if (!usernameHash) {
        return send(res, 409);
      }

      return { usernameHash: toURLSafeBase64(usernameHash) };
    },
  );

  const confirmUsername = put(
    '/v1/accounts/username_hash/confirm',
    async (req, res) => {
      const device = await auth(req, res);
      if (!device) {
        return;
      }

      const body = UsernameConfirmationSchema.parse(await json(req));

      const result = await server.confirmUsername(device.uuid, body);

      if (!result) {
        return send(res, 409);
      }

      return send(res, 200);
    },
  );

  const deleteUsername = del('/v1/accounts/username_hash', async (req, res) => {
    const device = await auth(req, res);
    if (!device) {
      return;
    }

    await server.deleteUsername(device.uuid);

    return send(res, 204);
  },
  );

  const lookupByUsernameHash = get(
    '/v1/accounts/username_hash/:hash',
    async (req, res) => {
      const { hash = '' } = req.params;

      const uuid = await server.lookupByUsernameHash(fromURLSafeBase64(hash));

      if (!uuid) {
        return send(res, 404);
      }

      return { uuid };
    },
  );

  const putChallenge = put('/v1/challenge', async (req, res) => {
    const device = await auth(req, res);
    if (!device) {
      return;
    }

    return { ok: true };
  });

  //
  // GV2
  //

  const getGroup = get('/v1/groups', async (req, res) => {
    const auth = await groupAuthAndFetch(req, res);
    if (!auth) {
      return;
    }

    const { group } = auth;
    return send(res, 200, Proto.Group.encode(group.state).finish());
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

      return send(res, 200, Proto.Member.encode({
        joinedAtVersion: member.joinedAtVersion,
      }).finish());
    },
  );

  const getGroupLogs = get('/v1/groups/logs/:since', async (req, res) => {
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

    return send(
      res,
      200,
      Proto.GroupChanges.encode(group.getChangesSince(since)).finish(),
    );
  });

  // TODO(indutny): implement me
  const createGroup = put('/v1/groups', async (req, res) => {
    const auth = await groupAuth(req, res);
    if (!auth) {
      return;
    }

    const groupData = Proto.Group.decode(
      Buffer.from(await buffer(req)),
    );
    if (!groupData.title) {
      return send(res, 400, { error: 'Missing group title' });
    }
    if (
      !groupData.publicKey || !auth.publicParams.equals(groupData.publicKey)
    ) {
      return send(res, 400, { error: 'Invalid group public key' });
    }

    await server.createGroup(groupData);

    // TODO(indutny): verify that creator is a member

    return send(res, 200);
  });

  const modifyGroup = patch('/v1/groups', async (req, res) => {
    const auth = await groupAuthAndFetch(req, res);
    if (!auth) {
      return;
    }

    const actions = Proto.GroupChange.Actions.decode(
      Buffer.from(await buffer(req)),
    );

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

      return send(
        res,
        200,
        Proto.GroupChange.encode(modifyResult.signedChange).finish(),
      );
    } catch (error) {
      assert(error instanceof Error);

      debug('Failed to modify group', error.stack);

      // TODO(indutny): would be nice to give 403 here
      return send(res, 500, { error: error.stack });
    }

    return send(res, 200, Proto.Group.encode(group.state).finish());
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

    return send(res, 200, Proto.StorageItems.encode({
      items,
    }).finish());
  });

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const dummyAuth = (response: any): RouteHandler => {
    return async (req, res) => {
      const device = await auth(req, res);
      if (!device) {
        return;
      }

      return response;
    };
  };

  const notFoundAfterAuth: RouteHandler = async (req, res) => {
    const device = await auth(req, res);
    if (!device) {
      return;
    }

    debug('Unsupported request %s %s', req.method, req.url);
    return send(res, 404, { error: 'Not supported yet' });
  };

  const routes = router(
    // Sure, why not
    get('/v1/config', dummyAuth({ config: [] })),
    put('/v1/devices/unauthenticated_delivery', dummyAuth({ ok: true })),
    put('/v1/devices/capabilities', dummyAuth({ ok: true })),

    // TODO(indutny): support nameless devices? They use different route
    provisionDevice,
    getDeviceKeys,
    getAllDeviceKeys,
    getAttachment,
    getStickerPack,
    getSticker,

    putKeys,
    getKeys,

    whoami,
    reserveUsername,
    confirmUsername,
    deleteUsername,
    lookupByUsernameHash,

    putChallenge,

    // Technically these should live on a separate server, but who cares
    getGroup,
    getGroupVersion,
    getGroupLogs,
    createGroup,
    modifyGroup,

    getStorageManifest,
    getStorageManifestByVersion,
    putStorage,
    putStorageRead,

    // TODO(indutny): support this
    get('/v1/groups/token', notFound),

    get('/stickers/', notFound),
    get('/*', notFoundAfterAuth),
    put('/*', notFoundAfterAuth),
  );

  return (req, res) => {
    debug('got request %s %s', req.method, req.url);
    return routes(req, res);
  };
};
