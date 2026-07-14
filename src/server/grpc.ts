// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import assert from 'assert';
import type { ServerResponse } from 'http';
import { Buffer } from 'buffer';
import createDebug from 'debug';
import { stringify as stringifyUuid, v4 as uuidv4 } from 'uuid';
import { RequestHandler, buffer, send as sendRaw } from 'micro';
import {
  AugmentedRequestHandler as RouteHandler,
  del,
  get,
  head,
  options,
  patch,
  post,
  put,
  router,
} from 'microrouter';
import { ServiceId, Aci, Pni } from '@signalapp/libsignal-client';
import SealedSenderMultiRecipientMessage from '@signalapp/libsignal-client/dist/SealedSenderMultiRecipientMessage';
import { Message } from '../data/schemas';

import { DeviceId, RegistrationId, ServiceIdString } from '../types';
import { $services, org, signalservice as Proto } from '../../protos/compiled';
import { Server } from './base';
import { auth } from './common';

const debug = createDebug('mock:grpc');

const ALL_METHODS = [get, post, put, patch, del, head, options] as const;

function toServiceIdentifier(
  string: ServiceIdString,
): org.signal.chat.common.ServiceIdentifier.Params {
  const object = ServiceId.parseFromServiceIdString(string);
  if (object instanceof Pni) {
    return {
      identityType: org.signal.chat.common.IdentityType.IDENTITY_TYPE_PNI,
      uuid: object.getRawUuidBytes(),
    };
  }

  if (object instanceof Aci) {
    return {
      identityType: org.signal.chat.common.IdentityType.IDENTITY_TYPE_ACI,
      uuid: object.getRawUuidBytes(),
    };
  }

  throw new Error(`Invalid service id: ${string}`);
}

// gRPC status codes used by the mock.
const GRPC_STATUS_OK = 0;
const GRPC_STATUS_UNKNOWN = 2;

// A gRPC response over HTTP/2 always uses HTTP status 200; the actual gRPC
// status code is carried in the trailing HEADERS frame (`grpc-status`). `micro`
// has no notion of trailers, so we emit them via the HTTP/2 compat API. (Driving
// the raw stream directly conflicts with the Http2ServerResponse that `micro`
// holds and throws ERR_HTTP2_TRAILERS_ALREADY_SENT.)
function sendGrpcResponse(
  res: ServerResponse,
  body: Buffer,
  status: number,
  message?: string,
): void {
  const trailers: Record<string, string> = {
    'grpc-status': String(status),
  };
  if (message !== undefined) {
    // Per the gRPC spec, `grpc-message` is percent-encoded.
    trailers['grpc-message'] = encodeURIComponent(message);
  }

  res.writeHead(200, { 'content-type': 'application/grpc' });
  res.addTrailers(trailers);
  res.end(body);
}

function grpcRoute<Endpoint extends keyof typeof $services>(
  endpoint: Endpoint,
  handler: (
    request: ReturnType<(typeof $services)[Endpoint]['Request']['decode']>,
  ) => Promise<
    Parameters<(typeof $services)[Endpoint]['Response']['encode']>[0]
  >,
) {
  const definition = $services[endpoint];
  // TODO(indutny): enforce on type level
  if (definition.isRequestStream || definition.isResponseStream) {
    throw new Error(`Request/response stream is not supported`);
  }
  return post(`/${endpoint}`, async (req, res) => {
    try {
      const raw = await buffer(req);
      assert(Buffer.isBuffer(raw));
      assert(raw.buffer instanceof ArrayBuffer);

      if (raw.length < 5) {
        throw new Error('gRPC request is too short');
      }

      if (raw[0] !== 0) {
        throw new Error('Unsupported request compression');
      }

      const len = raw.readUint32BE(1);
      if (raw.length !== 5 + len) {
        throw new Error('Invalid gRPC request size');
      }

      const request = definition.Request.decode(
        raw.subarray(5, 5 + len) as Uint8Array<ArrayBuffer>,
      );

      const response = await handler(request as Parameters<typeof handler>[0]);

      const data = (
        definition.Response.encode as (
          params: unknown,
        ) => Uint8Array<ArrayBuffer>
      )(response);
      const header = Buffer.alloc(5);
      header.writeUint32BE(data.length, 1);
      sendGrpcResponse(res, Buffer.concat([header, data]), GRPC_STATUS_OK);
    } catch (error) {
      debug('gRPC handler error for %s', endpoint, error);
      sendGrpcResponse(
        res,
        Buffer.alloc(0),
        GRPC_STATUS_UNKNOWN,
        error instanceof Error ? error.message : String(error),
      );
    }
  });
}

export const createHandler = (server: Server): RequestHandler => {
  // gRPC

  async function onMultiRecipientMessage(
    request:
      | org.signal.chat.messages.SendMultiRecipientMessageRequest
      | org.signal.chat.messages.SendMultiRecipientStoryRequest,
  ): Promise<org.signal.chat.messages.SendMultiRecipientMessageResponse.Params> {
    const {
      message: givenMessage,
      // TODO(indutny): check it at all?
      // groupSendToken,
    } = request;

    if (givenMessage == null) {
      throw new Error('Missing message');
    }

    const { timestamp, payload } = givenMessage;

    const message = new SealedSenderMultiRecipientMessage(Buffer.from(payload));

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
          content: Buffer.from(message.messageForRecipient(recipient)).toString(
            'base64',
          ),
        });
      }
    }

    const results = await Promise.all(
      Array.from(listByServiceId.entries()).map(
        async ([serviceId, messages]) => {
          return {
            uuid: serviceId,
            prepared: await server.prepareMultiDeviceMessage(
              undefined,
              serviceId,
              messages,
              timestamp,
            ),
          };
        },
      ),
    );

    const mismatchedDevices = results.filter(({ prepared }) => {
      return prepared.status === 'incomplete' || prepared.status === 'stale';
    });

    if (mismatchedDevices.length > 0) {
      return {
        response: {
          mismatchedDevices: {
            mismatchedDevices: mismatchedDevices.map(({ uuid, prepared }) => {
              if (prepared.status === 'incomplete') {
                return {
                  serviceIdentifier: toServiceIdentifier(uuid),
                  missingDevices: prepared.missingDevices.slice(),
                  extraDevices: prepared.extraDevices.slice(),
                  staleDevices: null,
                };
              }

              assert.ok(prepared.status === 'stale');
              return {
                serviceIdentifier: toServiceIdentifier(uuid),
                missingDevices: null,
                extraDevices: null,
                staleDevices: prepared.staleDevices.slice(),
              };
            }),
          },
        },
      };
    }

    const uuids404 = results
      .filter(({ prepared }) => prepared.status === 'unknown')
      .map(({ uuid }) => uuid);

    const ok = results.filter(({ prepared }) => prepared.status === 'ok');

    await Promise.all(
      ok.map(({ prepared }) => {
        assert.ok(prepared.status === 'ok');
        return server.handlePreparedMultiDeviceMessage(
          undefined,
          prepared.targetServiceId,
          prepared.result,
        );
      }),
    );

    return {
      response: {
        success: {
          unresolvedRecipients: uuids404.map(toServiceIdentifier),
        },
      },
    };
  }

  const onSendMultiRecipientMessage = grpcRoute(
    'org.signal.chat.messages.MessagesAnonymous/SendMultiRecipientMessage',
    onMultiRecipientMessage,
  );

  const onSendMultiRecipientStory = grpcRoute(
    'org.signal.chat.messages.MessagesAnonymous/SendMultiRecipientStory',
    onMultiRecipientMessage,
  );

  const onLookupUsernameHash = grpcRoute(
    'org.signal.chat.account.AccountsAnonymous/LookupUsernameHash',
    async ({ usernameHash }) => {
      const uuid = await server.lookupByUsernameHash(Buffer.from(usernameHash));

      if (!uuid) {
        return {
          response: {
            notFound: {},
          },
        };
      }

      return {
        response: {
          serviceIdentifier: toServiceIdentifier(uuid),
        },
      };
    },
  );

  const onLookupUsernameLink = grpcRoute(
    'org.signal.chat.account.AccountsAnonymous/LookupUsernameLink',
    async ({ usernameLinkHandle }) => {
      const usernameCiphertext = await server.lookupByUsernameLink(
        stringifyUuid(usernameLinkHandle),
      );

      if (!usernameCiphertext) {
        return {
          response: {
            notFound: {},
          },
        };
      }

      return {
        response: {
          usernameCiphertext,
        },
      };
    },
  );

  const onGetUploadForm = grpcRoute(
    'org.signal.chat.attachments.Attachments/GetUploadForm',
    async () => {
      const { cdn, key, headers, signedUploadLocation } =
        await server.getAttachmentUploadForm('attachments', uuidv4());
      return {
        outcome: {
          uploadForm: {
            cdn,
            key,
            headers: new Map(Object.entries(headers)),
            signedUploadLocation,
          },
        },
      };
    },
  );

  const notFoundAfterAuth: RouteHandler = async (req, res) => {
    const device = await auth(server, req, res);
    if (!device) {
      return;
    }

    debug('Unsupported request %s %s', req.method, req.url);
    return sendRaw(res, 404, { error: 'Not supported yet' });
  };

  const routes = router(
    // gRPC
    onSendMultiRecipientMessage,
    onSendMultiRecipientStory,
    onLookupUsernameHash,
    onLookupUsernameLink,
    onGetUploadForm,

    ...ALL_METHODS.map((method) => method('/*', notFoundAfterAuth)),
  );

  return (req, res) => {
    debug('got request %s %s', req.method, req.url);
    try {
      res.once('finish', () => {
        debug('response %s %s', req.method, req.url, res.statusCode);
      });
      // eslint-disable-next-line @typescript-eslint/no-unsafe-return
      return routes(req, res);
    } catch (error) {
      assert(error instanceof Error);
      debug('request failure %s %s', req.method, req.url, error.stack);
      return sendRaw(res, 500, error.message);
    }
  };
};
