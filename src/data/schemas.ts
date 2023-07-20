// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import z from 'zod';

import { fromURLSafeBase64 } from '../util';

const SignedPreKeySchema = z.object({
  keyId: z.number(),
  publicKey: z.string(),
  signature: z.string(),
});
export type ServerSignedPreKey = z.infer<typeof SignedPreKeySchema>;

export const DeviceKeysSchema = z.object({
  identityKey: z.string(),
  preKeys: z.object({
    keyId: z.number(),
    publicKey: z.string(),
  }).array(),
  pqPreKeys: SignedPreKeySchema.array().optional(),
  pqLastResortPreKey: SignedPreKeySchema.optional(),
  signedPreKey: SignedPreKeySchema.optional(),
});

export type DeviceKeys = z.infer<typeof DeviceKeysSchema>;

export const MessageSchema = z.object({
  // NOTE: Envelope.Type
  type: z.number(),
  destinationDeviceId: z.number(),
  destinationRegistrationId: z.number(),
  content: z.string(),
});

export type Message = z.infer<typeof MessageSchema>;

export const MessageListSchema = z.object({
  messages: MessageSchema.array(),
  timestamp: z.number(),
});

export type MessageList = z.infer<typeof MessageListSchema>;

export const RegistrationDataSchema = z.object({
  registrationId: z.number(),
  pniRegistrationId: z.number(),
});

export const GroupStateSchema = z.object({
  publicKey: z.instanceof(Uint8Array),
  version: z.literal(0),
  accessControl: z.object({
    attributes: z.number(),
    members: z.number(),
    addFromInviteLink: z.number(),
  }),
  members: z.unknown().array().min(1),
});

export const UsernameReservationSchema = z.object({
  usernameHashes: z.string().transform(
    fromURLSafeBase64,
  ).array().min(1).max(20),
});

export type UsernameReservation = z.infer<typeof UsernameReservationSchema>;

export const UsernameConfirmationSchema = z.object({
  usernameHash: z.string().transform(fromURLSafeBase64),
  zkProof: z.string().transform(fromURLSafeBase64),
  encryptedUsername: z.string().transform(fromURLSafeBase64).optional(),
});

export type UsernameConfirmation = z.infer<typeof UsernameConfirmationSchema>;

export const PutUsernameLinkSchema = z.object({
  usernameLinkEncryptedValue: z.string().transform(fromURLSafeBase64),
});

export type PutUsernameLink = z.infer<typeof PutUsernameLinkSchema>;
