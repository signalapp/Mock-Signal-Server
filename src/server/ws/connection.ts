// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import assert from 'assert';
import { Buffer } from 'buffer';
import { IncomingMessage } from 'http';
import { parse as parseURL } from 'url';
import { timingSafeEqual } from 'crypto';
import createDebug from 'debug';
import {
  ProfileKeyCredentialRequest,
} from '@signalapp/libsignal-client/zkgroup';

import WebSocket from 'ws';

import { signalservice as Proto } from '../../../protos/compiled';
import { Device } from '../../data/device';
import { JSONMessage, JSONMessageList } from '../../data/json.d';
import { UUID, UUIDKind } from '../../types';
import { generateAccessKeyVerifier } from '../../crypto';
import { Server } from '../base';
import {
  combineMultiRecipientMessage,
  parseAuthHeader,
  parseMultiRecipientMessage,
} from '../../util';

import { Service, WSRequest, WSResponse } from './service';
import { Handler, Router } from './router';

const debug = createDebug('mock:ws:connection');

export class Connection extends Service {
  private device: Device | undefined;
  private readonly router = new Router();

  constructor(
    private readonly request: IncomingMessage,
    ws: WebSocket,
    private readonly server: Server,
  ) {
    super(ws);

    const getProfile: Handler = async (
      params,
      _,
      headers,
      { credentialType = 'profileKey' } = {},
    ) => {
      const uuid = params.uuid as string;

      const device = await this.server.getDeviceByUUID(uuid);
      if (!device) {
        return [ 404, { error: 'Device not found' } ];
      }

      if (this.device) {
        // Authenticated
      } else if (!device.accessKey || !headers['unidentified-access-key']) {
        return [ 401, { error: 'Not authenticated' } ];
      } else {
        const accessKey = Buffer.from(
          headers['unidentified-access-key'],
          'base64',
        );
        if (!timingSafeEqual(accessKey, device.accessKey)) {
          return [ 401, { error: 'Invalid access key' } ];
        }
      }

      let credential: Buffer | undefined;
      let pniCredential: Buffer | undefined;
      if (params.request) {
        const request = new ProfileKeyCredentialRequest(
          Buffer.from(params.request as string, 'hex'),
        );
        if (credentialType === 'profileKey') {
          credential = await this.server.issueProfileKeyCredential(
            device,
            request,
          );
        } else if (credentialType === 'pni') {
          pniCredential = await this.server.issuePniCredential(
            device,
            request,
          );
        } else {
          return [ 400, { error: 'Unsupported credential type' } ];
        }
      }

      const uuidKind = device.getUUIDKind(uuid);
      const identityKey = await device.getIdentityKey(uuidKind);

      return [ 200, {
        name: device.profileName,
        identityKey: identityKey.serialize().toString('base64'),
        unrestrictedUnidentifiedAccess: false,
        unidentifiedAccess: device.accessKey ?
          generateAccessKeyVerifier(device.accessKey) : undefined,
        capabilities: {
          announcementGroup: true,
          'gv2-3': true,
          'gv1-migration': true,
          senderKey: true,
        },
        credential: credential?.toString('base64'),
        pniCredential: pniCredential?.toString('base64'),
      } ];
    };
    this.router.get('/v1/profile/:uuid', getProfile);
    this.router.get('/v1/profile/:uuid/:version', getProfile);
    this.router.get('/v1/profile/:uuid/:version/:request', getProfile);

    const requireAuth = (handler: Handler): Handler => {
      return async (params, body, headers) => {
        if (!this.device) {
          return [ 401, { error: 'Not authorized' } ];
        }

        return handler(params, body, headers);
      };
    };

    this.router.get('/v1/config', requireAuth(async () => {
      return [ 200, {
        config: [
          { name: 'desktop.gv2', enabled: true },
          { name: 'desktop.gv2Admin', enabled: true },
          { name: 'desktop.internalUser', enabled: true },
          { name: 'desktop.sendSenderKey2', enabled: true },
          { name: 'desktop.sendSenderKey3', enabled: true },
          { name: 'desktop.senderKey.retry', enabled: true },
          { name: 'desktop.senderKey.send', enabled: true },
          { name: 'desktop.storage', enabled: true },
          { name: 'desktop.storageWrite3', enabled: true },
          { name: 'desktop.messageRequests', enabled: true },
          {
            name: 'global.groupsv2.maxGroupSize',
            value: '32',
            enabled: true,
          },
          {
            name: 'global.groupsv2.groupSizeHardLimit',
            value: '64',
            enabled: true,
          },
        ],
      } ];
    }));

    this.router.put(
      '/v1/messages/multi_recipient',
      async (_params, body) => {
        if (!body) {
          return [ 400, { error: 'Missing body' } ];
        }

        const {
          recipients,
          commonMaterial,
        } = parseMultiRecipientMessage(Buffer.from(body));

        const listByUUID = new Map<UUID, Array<JSONMessage>>();

        for (const recipient of recipients) {
          const {
            uuid,
            deviceId,
            registrationId,
            material,
          } = recipient;

          let list: Array<JSONMessage> | undefined = listByUUID.get(uuid);
          if (!list) {
            list = [];
            listByUUID.set(uuid, list);
          }

          list.push({
            type: Proto.Envelope.Type.UNIDENTIFIED_SENDER,
            destinationDeviceId: deviceId,
            destinationRegistrationId: registrationId,
            content: combineMultiRecipientMessage({
              material,
              commonMaterial,
            }).toString('base64'),
          });
        }

        // TODO(indutny): verify access key xor

        const results = await Promise.all(
          Array.from(listByUUID.entries()).map(async (
            [ uuid, messages ],
          ) => {
            return {
              uuid,
              prepared: await this.server.prepareMultiDeviceMessage(
                undefined,
                uuid,
                messages,
              ),
            };
          }),
        );

        const incomplete = results.filter(
          ({ prepared }) => prepared.status === 'incomplete',
        );

        if (incomplete.length !== 0) {
          return [
            409,
            incomplete.map(({ uuid, prepared }) => {
              assert.ok(prepared.status === 'incomplete');
              return {
                uuid,
                devices: {
                  missingDevices: prepared.missingDevices,
                  extraDevices: prepared.extraDevices,
                },
              };
            }),
          ];
        }

        const stale = results.filter(
          ({ prepared }) => prepared.status === 'stale',
        );

        if (stale.length !== 0) {
          return [
            410,
            stale.map(({ uuid, prepared }) => {
              assert.ok(prepared.status === 'stale');
              return { uuid, devices: { staleDevices: prepared.staleDevices } };
            }),
          ];
        }

        const uuids404 = results.filter(
          ({ prepared }) => prepared.status === 'unknown',
        ).map(({ uuid }) => uuid);

        const ok = results.filter(({ prepared }) => prepared.status === 'ok');

        await Promise.all(ok.map(({ prepared }) => {
          assert.ok(prepared.status === 'ok');
          return this.server.handlePreparedMultiDeviceMessage(
            undefined,
            prepared.targetUUID,
            prepared.result,
          );
        }));

        return [ 200, { uuids404 } ];
      },
    );

    this.router.put('/v1/messages/:uuid', async (params, body) => {
      if (!body) {
        return [ 400, { error: 'Missing body' } ];
      }

      const { messages }: JSONMessageList = JSON.parse(
        Buffer.from(body).toString(),
      );

      // TODO(indutny): access key or auth!

      const prepared = await this.server.prepareMultiDeviceMessage(
        this.device,
        params.uuid as string,
        messages,
      );

      switch (prepared.status) {
      case 'ok':
        await this.server.handlePreparedMultiDeviceMessage(
          this.device,
          prepared.targetUUID,
          prepared.result,
        );
        return [ 200, { ok: true } ];
      case 'unknown':
        return [ 404, { error: 'Not found' } ];
      case 'incomplete':
        return [ 409, {
          missingDevices: prepared.missingDevices,
          extraDevices: prepared.extraDevices,
        } ];
      case 'stale':
        return [ 410, { staleDevices: prepared.staleDevices } ];
      }
    });

    this.router.put('/v1/devices/capabilities', requireAuth(async () => {
      return [ 200, { ok: true } ];
    }));

    this.router.put(
      '/v1/devices/unauthenticated_delivery',
      requireAuth(async () => {
        return [ 200, { ok: true } ];
      }),
    );

    this.router.get(
      '/v1/certificate/delivery',
      requireAuth(async () => {
        const device = this.device;
        if (!device) {
          throw new Error('No support for unauthorized delivery');
        }

        const certificate = await this.server.getSenderCertificate(device);

        return [
          200,
          { certificate: certificate.serialize().toString('base64') },
        ];
      }),
    );

    this.router.put('/v1/devices/:code', async (params, body, headers) => {
      const { error, username, password } = parseAuthHeader(
        headers.authorization,
      );
      if (error) {
        return [ 400, { error } ];
      }
      if (!username || !password) {
        return [ 400, { error: 'Invalid authorization header' } ];
      }
      if (!body) {
        return [ 400, { error: 'Missing body' } ];
      }

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const json = JSON.parse(Buffer.from(body).toString());
      if (typeof json.registrationId !== 'number') {
        return [ 400, { error: 'Invalid registration id' } ];
      }

      const device = await server.provisionDevice(
        username,
        password,
        params.code as string,
        json.registrationId as number);

      return [ 200, {
        deviceId: device.deviceId,
        uuid: device.uuid,
        pni: device.pni,
      } ];
    });

    //
    // Groups
    //

    this.router.get(
      '/v1/certificate/group/:from/:to',
      async (params, _body, _heaers, { identity = 'aci' } = {}) => {
        const device = this.device;
        if (!device) {
          throw new Error('No support for unauthorized delivery');
        }

        let uuidKind = UUIDKind.ACI;
        if (identity === 'aci') {
          uuidKind = UUIDKind.ACI;
        } else if (identity === 'pni') {
          uuidKind = UUIDKind.PNI;
        } else {
          return [ 400, {error: 'Invalid identity query'} ];
        }

        const uuid = device.getUUIDByKind(uuidKind);

        return [
          200,
          {
            credentials:  await this.server.getGroupCredentials(uuid, {
              from: parseInt(params.from as string, 10),
              to: parseInt(params.to as string, 10),
            }),
          },
        ];
      },
    );

    //
    // Storage Service
    //

    this.router.get('/v1/storage/auth', async () => {
      const device = this.device;
      if (!device) {
        throw new Error('Storage credentials require authorization');
      }

      return [ 200, await server.getStorageAuth(device) ];
    });
  }

  public async start(): Promise<void> {
    debug('Got a websocket connection', this.request.url);
    const url = this.request.url;
    if (!url) {
      throw new Error('Request must have url');
    }

    if (url.startsWith('/v1/websocket/provisioning')) {
      const uuid = await this.server.generateUUID();
      try {
        await this.handleProvision(uuid);
      } catch (error) {
        await this.server.releaseUUID(uuid);
        throw error;
      }
      return;
    }

    if (url.startsWith('/v1/websocket/?')) {
      return await this.handleNormal(url);
    }
  }

  public async sendMessage(message: Buffer | 'empty'): Promise<void> {
    let response;
    if (message === 'empty') {
      response = await this.send('PUT', '/api/v1/queue/empty', {});
    } else {
      response = await this.send('PUT', '/api/v1/message', {
        body: message,
      });
    }

    assert.strictEqual(response.status, 200,
      `WebSocket send error ${response.status} ${response.message}`);
  }

  //
  // Service implementation
  //

  protected async handleRequest(
    request: WSRequest,
  ): Promise<WSResponse> {
    return this.router.run(request);
  }

  //
  // Private
  //

  private async handleProvision(uuid: UUID) {
    {
      const { status } = await this.send('PUT', '/v1/address', {
        body: Proto.ProvisioningUuid.encode({
          uuid,
        }).finish(),
      });
      assert.strictEqual(status, 200);
    }

    {
      const { envelope } = await this.server.getProvisioningResponse(uuid);
      const { status } = await this.send('PUT', '/v1/message', {
        body: envelope,
      });
      assert.strictEqual(status, 200);
    }
  }

  private async handleNormal(url: string) {
    const query = parseURL(url, true).query || {};
    if (!query.login ||
        Array.isArray(query.login) ||
        !query.password ||
        Array.isArray(query.password)) {
      debug('Unauthorized WebSocket connection');
      return;
    }

    const device = await this.server.auth(query.login, query.password);
    if (!device) {
      debug('Invalid WebSocket credentials %j', query);
      this.ws.close();
      return;
    }

    this.device = device;

    this.ws.once('close', () => {
      this.server.removeWebSocket(device, this);
    });

    await this.server.addWebSocket(device, this);
  }
}
