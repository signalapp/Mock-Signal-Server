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
  get,
  put,
  router,
} from 'microrouter';
import { PublicKey } from '@signalapp/signal-client';
import { GroupPublicParams } from '@signalapp/signal-client/zkgroup';
import createDebug from 'debug';

import { Server } from './base';
import { ServerGroup } from './group';
import { Device } from '../data/device';
import { ParseAuthHeaderResult, parseAuthHeader } from '../util';
import { JSONDeviceKeys } from '../data/json.d';
import { signalservice as Proto } from '../../protos/compiled';

const debug = createDebug('mock:http');

const parsePassword = (req: ServerRequest): ParseAuthHeaderResult => {
  return parseAuthHeader(req.headers.authorization);
};

const sendDevicesKeys = async (
  res: ServerResponse,
  devices: ReadonlyArray<Device>,
): Promise<void> => {
  const [ primary ] = devices;
  assert(primary !== undefined, 'Empty device list');

  const identityKey = await primary.getIdentityKey();

  send(res, 200, {
    identityKey: identityKey.serialize().toString('base64'),
    devices: await Promise.all(devices.map(async (device) => {
      const { signedPreKey, preKey } =
        await device.popSingleUseKey();
      return {
        deviceId: device.deviceId,
        registrationId: device.registrationId,
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

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const body = await json(req) as any;
    if (typeof body.registrationId !== 'number') {
      return send(res, 400, { error: 'Invalid registration id' });
    }

    const device = await server.provisionDevice(
      username,
      password,
      req.params.code,
      body.registrationId);

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

    return await sendDevicesKeys(res, [ device ]);
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

    return await sendDevicesKeys(res, devices);
  });

  //
  // CDN
  //

  const getAttachment = get('/attachments/:key/:subkey', async (req) => {
    const { key, subkey } = req.params;
    return await server.fetchAttachment(`${key}/${subkey}`);
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

  async function groupAuth(
    req: ServerRequest,
    res: ServerResponse,
  ): Promise<ServerGroup | undefined> {
    const { error, username, password } = parsePassword(req);

    if (error) {
      send(res, 400, { error });
      return undefined;
    }
    if (!username || !password) {
      send(res, 400, { error: 'Invalid authorization header' });
      return undefined;
    }

    const publicParams = new GroupPublicParams(Buffer.from(username, 'hex'));

    // TODO(indutny): validate password

    const group = await server.getGroup(publicParams);
    if (!group) {
      send(res, 404, { error: 'Group not found' });
      return undefined;
    }

    return group;
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

  const putKeys = put('/v2/keys', async (req, res) => {
    const device = await auth(req, res);
    if (!device) {
      return;
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const body: JSONDeviceKeys = await json(req) as any;
    try {
      const parseKey = (base64: string): PublicKey => {
        return PublicKey.deserialize(Buffer.from(base64, 'base64'));
      };

      await server.updateDeviceKeys(device, {
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

    return { count: await device.getSingleUseKeyCount() };
  });

  const whoami = get('/v1/accounts/whoami', async (req, res) => {
    const device = await auth(req, res);
    if (!device) {
      return;
    }

    return { uuid: device.uuid, pni: device.pni, number: device.number };
  });

  //
  // GV2
  //

  const getGroup = get('/v1/groups', async (req, res) => {
    const group = await groupAuth(req, res);
    if (!group) {
      return;
    }

    return send(res, 200, Proto.Group.encode(group.getState()).finish());
  });

  const getGroupVersion = get('/v1/groups/joined_at_version', async (req, res) => {
    const group = await groupAuth(req, res);
    if (!group) {
      return;
    }

    // TODO(indutny): support this for real?
    return send(res, 200, Proto.Member.encode({
      joinedAtVersion: 0,
    }).finish());
  });

  const getGroupLogs = get('/v1/groups/logs/:since', async (req, res) => {
    const group = await groupAuth(req, res);
    if (!group) {
      return;
    }

    const since = parseInt(req.params.since, 10);

    return send(
      res,
      200,
      Proto.GroupChanges.encode(group.getChangesSince(since)).finish(),
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

    const items = (readOperation.readKey || []).map(async (key) => {
      return {
        key,
        value: await server.getStorageItem(device, Buffer.from(key)),
      };
    });

    return send(res, 200, Proto.StorageItems.encode({
      items: await Promise.all(items),
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

    putKeys,
    getKeys,

    whoami,

    // Technically these should live on a separate server, but who cares
    getGroup,
    getGroupVersion,
    getGroupLogs,

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
