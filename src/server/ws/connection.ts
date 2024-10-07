// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import assert from 'assert';
import { Buffer } from 'buffer';
import { IncomingMessage } from 'http';
import { timingSafeEqual } from 'crypto';
import createDebug from 'debug';
import { ProfileKeyCredentialRequest } from '@signalapp/libsignal-client/zkgroup';
import SealedSenderMultiRecipientMessage from '@signalapp/libsignal-client/dist/SealedSenderMultiRecipientMessage';

import WebSocket from 'ws';
import { v4 as uuidv4 } from 'uuid';

import { signalservice as Proto } from '../../../protos/compiled';
import { Device } from '../../data/device';
import {
  AtomicLinkingDataSchema,
  BackupHeadersSchema,
  Message,
  MessageListSchema,
  SetBackupIdSchema,
  SetBackupKeySchema,
} from '../../data/schemas';
import {
  DeviceId,
  ProvisionIdString,
  ProvisioningCode,
  RegistrationId,
  ServiceIdKind,
  ServiceIdString,
  untagPni,
} from '../../types';
import {
  decodeKyberPreKey,
  decodeSignedPreKey,
  generateAccessKeyVerifier,
} from '../../crypto';
import { Server } from '../base';
import { parseAuthHeader } from '../../util';

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
      { credentialType } = {},
    ) => {
      const serviceId = params.serviceId as ServiceIdString;

      const target = await this.server.getDeviceByServiceId(serviceId);
      if (!target) {
        return [404, { error: 'Device not found' }];
      }

      if (this.server.isUnregistered(serviceId)) {
        return [404, { error: 'Unregistered' }];
      }

      const accessError = this.checkAccessKey(target, headers);
      if (accessError !== undefined) {
        return [401, { error: accessError }];
      }

      let credential: Buffer | undefined;
      if (params.request) {
        const request = new ProfileKeyCredentialRequest(
          Buffer.from(params.request as string, 'hex'),
        );
        if (credentialType === 'expiringProfileKey') {
          credential = await this.server.issueExpiringProfileKeyCredential(
            target,
            request,
          );
        } else {
          return [400, { error: 'Unsupported credential type' }];
        }
      }

      const serviceIdKind = target.getServiceIdKind(serviceId);
      const identityKey = await target.getIdentityKey(serviceIdKind);

      return [
        200,
        {
          name: target.profileName?.toString('base64'),
          identityKey: identityKey.serialize().toString('base64'),
          unrestrictedUnidentifiedAccess: false,
          unidentifiedAccess: target.accessKey
            ? generateAccessKeyVerifier(target.accessKey).toString('base64')
            : undefined,
          capabilities: target.capabilities,
          credential: credential?.toString('base64'),
        },
      ];
    };
    this.router.get('/v1/profile/:serviceId', getProfile);
    this.router.get('/v1/profile/:serviceId/:version', getProfile);
    this.router.get('/v1/profile/:serviceId/:version/:request', getProfile);

    const requireAuth = (handler: Handler): Handler => {
      return async (params, body, headers, query) => {
        if (!this.device) {
          return [401, { error: 'Not authorized' }];
        }

        return handler(params, body, headers, query);
      };
    };

    this.router.get(
      '/v1/config',
      requireAuth(async () => {
        return [
          200,
          {
            config: [
              { name: 'desktop.internalUser', enabled: true },
              { name: 'desktop.senderKey.retry', enabled: true },
              { name: 'desktop.backup.credentialFetch', enabled: true },
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
            serverEpochTime: Date.now() / 1000,
          },
        ] as const;
      }),
    );

    this.router.put('/v1/messages/multi_recipient', async (_params, body) => {
      if (!body) {
        return [400, { error: 'Missing body' }];
      }

      const message = new SealedSenderMultiRecipientMessage(Buffer.from(body));

      const listByServiceId = new Map<ServiceIdString, Array<Message>>();

      const recipients = message.recipientsByServiceIdString();
      for (const [serviceId, recipient] of Object.entries(recipients)) {
        let list: Array<Message> | undefined = listByServiceId.get(
          serviceId as ServiceIdString,
        );
        if (!list) {
          list = [];
          listByServiceId.set(serviceId as ServiceIdString, list);
        }

        for (const [i, deviceId] of recipient.deviceIds.entries()) {
          const registrationId = recipient.registrationIds.at(i);

          list.push({
            type: Proto.Envelope.Type.UNIDENTIFIED_SENDER,
            destinationDeviceId: deviceId as DeviceId,
            destinationRegistrationId: registrationId as RegistrationId,
            content: message.messageForRecipient(recipient).toString('base64'),
          });
        }
      }

      // TODO(indutny): verify access key xor

      const results = await Promise.all(
        Array.from(listByServiceId.entries()).map(
          async ([serviceId, messages]) => {
            return {
              uuid: serviceId,
              prepared: await this.server.prepareMultiDeviceMessage(
                undefined,
                serviceId,
                messages,
              ),
            };
          },
        ),
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

      const uuids404 = results
        .filter(({ prepared }) => prepared.status === 'unknown')
        .map(({ uuid }) => uuid);

      const ok = results.filter(({ prepared }) => prepared.status === 'ok');

      await Promise.all(
        ok.map(({ prepared }) => {
          assert.ok(prepared.status === 'ok');
          return this.server.handlePreparedMultiDeviceMessage(
            undefined,
            prepared.targetServiceId,
            prepared.result,
          );
        }),
      );

      return [200, { uuids404 }];
    });

    this.router.put(
      '/v1/messages/:serviceId',
      async (params, body, headers, query = {}) => {
        if (!body) {
          return [400, { error: 'Missing body' }];
        }

        const { messages } = MessageListSchema.parse(
          JSON.parse(Buffer.from(body).toString()),
        );

        const targetServiceId = params.serviceId as ServiceIdString;
        const target = await this.server.getDeviceByServiceId(targetServiceId);
        if (!target) {
          return [404, { error: 'Device not found' }];
        }

        if (query.story !== 'true') {
          const accessError = this.checkAccessKey(target, headers);
          if (accessError !== undefined) {
            return [401, { error: accessError }];
          }
        }

        if (this.server.isUnregistered(targetServiceId)) {
          return [404, { error: 'Unregistered' }];
        }

        if (
          this.device &&
          this.server.isSendRateLimited({
            source: this.device.aci,
            target: targetServiceId,
          })
        ) {
          return [428, { token: 'token', options: ['recaptcha'] }];
        }

        const prepared = await this.server.prepareMultiDeviceMessage(
          this.device,
          params.serviceId as ServiceIdString,
          messages,
        );

        switch (prepared.status) {
          case 'ok':
            await this.server.handlePreparedMultiDeviceMessage(
              this.device,
              prepared.targetServiceId,
              prepared.result,
            );
            return [200, { ok: true }];
          case 'unknown':
            return [404, { error: 'Not found' }];
          case 'incomplete':
            return [
              409,
              {
                missingDevices: prepared.missingDevices,
                extraDevices: prepared.extraDevices,
              },
            ];
          case 'stale':
            return [410, { staleDevices: prepared.staleDevices }];
        }
      },
    );

    this.router.put(
      '/v1/devices/capabilities',
      requireAuth(async () => {
        return [200, { ok: true }];
      }),
    );

    this.router.put(
      '/v1/devices/unauthenticated_delivery',
      requireAuth(async () => {
        return [200, { ok: true }];
      }),
    );

    this.router.get(
      '/v1/certificate/delivery',
      requireAuth(async () => {
        const device = this.device;
        if (!device) {
          debug(
            '/v1/certificate/delivery: No support for unauthorized delivery',
          );
          return [401, { error: 'Not authorized' }];
        }

        const certificate = await this.server.getSenderCertificate(device);

        return [
          200,
          { certificate: certificate.serialize().toString('base64') },
        ];
      }),
    );

    this.router.put('/v1/devices/link', async (_params, body, headers) => {
      const { error, username, password } = parseAuthHeader(
        headers.authorization,
      );
      if (error) {
        return [400, { error }];
      }
      if (!username || !password) {
        return [400, { error: 'Invalid authorization header' }];
      }
      if (!body) {
        return [400, { error: 'Missing body' }];
      }

      const {
        verificationCode,
        accountAttributes,
        aciSignedPreKey,
        pniSignedPreKey,
        aciPqLastResortPreKey,
        pniPqLastResortPreKey,
      } = AtomicLinkingDataSchema.parse(
        JSON.parse(Buffer.from(body).toString()),
      );

      const { registrationId, pniRegistrationId } = accountAttributes;

      const device = await server.provisionDevice({
        number: username,
        password,
        provisioningCode: verificationCode as ProvisioningCode,
        registrationId,
        pniRegistrationId,
      });

      const primary = await server.getDeviceByServiceId(device.aci);
      if (!primary) {
        throw new Error('Primary device not found');
      }

      await server.updateDeviceKeys(device, ServiceIdKind.ACI, {
        lastResortKey: decodeKyberPreKey(aciPqLastResortPreKey),
        signedPreKey: decodeSignedPreKey(aciSignedPreKey),
      });
      await server.updateDeviceKeys(device, ServiceIdKind.PNI, {
        lastResortKey: decodeKyberPreKey(pniPqLastResortPreKey),
        signedPreKey: decodeSignedPreKey(pniSignedPreKey),
      });

      return [
        200,
        {
          deviceId: device.deviceId,
          uuid: device.aci,
          pni: untagPni(device.pni),
        },
      ];
    });

    //
    // Groups
    //

    this.router.get(
      '/v1/certificate/auth/group',
      async (_params, _body, _headers, query = {}) => {
        const device = this.device;
        if (!device) {
          debug(
            '/v1/certificate/auth/group: No support for unauthorized delivery',
          );
          return [401, { error: 'Not authorized' }];
        }

        const {
          redemptionStartSeconds: from,
          redemptionEndSeconds: to,
          zkcCredential,
        } = query;

        return [
          200,
          {
            credentials: await this.server.getGroupCredentials(
              device,
              {
                from: parseInt(from as string, 10),
                to: parseInt(to as string, 10),
              },
              { zkc: zkcCredential === 'true' },
            ),
            callLinkAuthCredentials:
              await this.server.getCallLinkAuthCredentials(device, {
                from: parseInt(from as string, 10),
                to: parseInt(to as string, 10),
              }),
            pni: untagPni(device.pni),
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

      return [200, await server.getStorageAuth(device)];
    });

    //
    // Backups
    //

    this.router.put(
      '/v1/archives/backupid',
      requireAuth(async (_params, body) => {
        const device = this.device;
        assert(device);

        if (!body) {
          return [400, { error: 'Missing body' }];
        }

        const backupId = SetBackupIdSchema.parse(JSON.parse(body.toString()));
        await server.setBackupId(device, backupId);
        return [200, { ok: true }];
      }),
    );

    this.router.get(
      '/v1/archives/auth',
      requireAuth(async (_params, _body, _headers, query = {}) => {
        const device = this.device;
        assert(device);

        const { redemptionStartSeconds: from, redemptionEndSeconds: to } =
          query;

        const credentials = await this.server.getBackupCredentials(device, {
          from: parseInt(from as string, 10),
          to: parseInt(to as string, 10),
        });
        if (credentials === undefined) {
          return [404, { error: 'backup id not set' }];
        }

        return [
          200,
          {
            credentials,
          },
        ];
      }),
    );

    this.router.put('/v1/archives/keys', async (_params, body, headers) => {
      if (this.device) {
        return [400, { error: 'Extraneous authentication' }];
      }

      if (!body) {
        return [400, { error: 'Missing body' }];
      }

      const backupKey = SetBackupKeySchema.parse(JSON.parse(body.toString()));
      await server.setBackupKey(BackupHeadersSchema.parse(headers), backupKey);
      return [200, { ok: true }];
    });

    this.router.post('/v1/archives', async (_params, _body, headers) => {
      if (this.device) {
        return [400, { error: 'Extraneous authentication' }];
      }

      await server.refreshBackup(BackupHeadersSchema.parse(headers));
      return [200, { ok: true }];
    });

    this.router.get('/v1/archives', async (_params, _body, headers) => {
      if (this.device) {
        return [400, { error: 'Extraneous authentication' }];
      }

      return [
        200,
        await server.getBackupInfo(BackupHeadersSchema.parse(headers)),
      ];
    });

    this.router.get(
      '/v1/archives/auth/read',
      async (_params, _body, headers, params = {}) => {
        if (this.device) {
          return [400, { error: 'Extraneous authentication' }];
        }

        if (params.cdn !== '3') {
          return [400, { error: 'Invalid cdn query param' }];
        }

        return [
          200,
          {
            headers: await server.getBackupCDNAuth(
              BackupHeadersSchema.parse(headers),
            ),
          },
        ];
      },
    );

    this.router.get(
      '/v1/archives/upload/form',
      async (_params, _body, headers) => {
        if (this.device) {
          return [400, { error: 'Extraneous authentication' }];
        }

        return [
          200,
          await this.server.getBackupUploadForm(
            BackupHeadersSchema.parse(headers),
          ),
        ];
      },
    );

    //
    // Keepalive
    //

    this.router.get('/v1/keepalive', async () => {
      return [200, { ok: true }];
    });

    //
    // Attachment upload forms
    //

    this.router.get('/v4/attachments/form/upload', async () => {
      const key = uuidv4();
      return [200, await this.server.getAttachmentUploadForm(key)];
    });
  }

  public async start(): Promise<void> {
    debug('Got a websocket connection', this.request.url);
    const url = this.request.url;
    if (!url) {
      throw new Error('Request must have url');
    }

    if (url.startsWith('/v1/websocket/provisioning')) {
      const id = await this.server.generateProvisionId();
      try {
        await this.handleProvision(id);
      } catch (error) {
        await this.server.releaseProvisionId(id);
        throw error;
      }
      return;
    }

    if (url.startsWith('/v1/websocket/?')) {
      return await this.handleNormal(this.request);
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

    assert.strictEqual(
      response.status,
      200,
      `WebSocket send error ${response.status} ${response.message}`,
    );
  }

  //
  // Service implementation
  //

  protected async handleRequest(request: WSRequest): Promise<WSResponse> {
    return this.router.run(request);
  }

  //
  // Private
  //

  private async handleProvision(id: ProvisionIdString) {
    {
      const { status } = await this.send('PUT', '/v1/address', {
        body: Proto.ProvisioningUuid.encode({
          uuid: id,
        }).finish(),
      });
      assert.strictEqual(status, 200);
    }

    {
      const { envelope } = await this.server.getProvisioningResponse(id);
      const { status } = await this.send('PUT', '/v1/message', {
        body: envelope,
      });
      assert.strictEqual(status, 200);
    }
  }

  private async handleNormal(incomingMessage: IncomingMessage) {
    const authHeaders = incomingMessage.headers.authorization;
    if (!authHeaders) {
      debug('Websocket connection does not include Authorization header');
      return;
    }
    const { error, username, password } = parseAuthHeader(authHeaders, {
      allowEmptyPassword: true,
    });

    if (error || !username) {
      debug(
        'Invalid Authorization header for websocket connection @ %s: %s',
        error,
        authHeaders,
      );
      return;
    }

    const device = await this.server.auth(username, password);
    if (!device) {
      debug('Invalid WebSocket credentials @ %s: %j', incomingMessage.url, {
        username,
        password,
      });
      this.ws.close(3000);
      return;
    }

    this.device = device;
    this.router.setIsAuthenticated(true);

    this.ws.once('close', () => {
      this.server.removeWebSocket(device, this);
    });

    await this.server.addWebSocket(device, this);
  }

  private checkAccessKey(
    target: Device,
    headers: Record<string, string>,
  ): string | undefined {
    if (this.device) {
      // Authenticated
    } else if (!target.accessKey || !headers['unidentified-access-key']) {
      return 'Not authenticated';
    } else {
      const accessKey = Buffer.from(
        headers['unidentified-access-key'],
        'base64',
      );
      if (!timingSafeEqual(accessKey, target.accessKey)) {
        return 'Invalid access key';
      }
    }

    return undefined;
  }
}
