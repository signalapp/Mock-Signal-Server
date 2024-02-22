// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import assert from 'assert';
import fs from 'fs/promises';
import path from 'path';

export type Certificates = Readonly<{
  certificateAuthority: string;
  genericServerPublicParams: string;
  serverPublicParams: string;
  serverTrustRoot: string;
}>;

const CERTS_DIR = path.join(
  __dirname,
  '..',
  '..',
  'certs',
);

async function loadString(file: string): Promise<string> {
  const raw = await fs.readFile(path.join(CERTS_DIR, file));
  return raw.toString();
}

async function loadJSONProperty(
  file: string,
  property: string,
): Promise<string> {
  const raw = await fs.readFile(path.join(CERTS_DIR, file));
  const obj = JSON.parse(raw.toString());
  const value = obj[property];

  assert(
    typeof value === 'string',
    `Expected string at: ${file}/${property}`,
  );
  return value;
}

export async function load(): Promise<Certificates> {
  const [
    certificateAuthority,
    genericServerPublicParams,
    serverPublicParams,
    serverTrustRoot,
  ] = await Promise.all([
    loadString('ca-cert.pem'),
    loadJSONProperty(
      'zk-params.json',
      'genericPublicParams',
    ),
    loadJSONProperty(
      'zk-params.json',
      'publicParams',
    ),
    loadJSONProperty('trust-root.json', 'publicKey'),
  ]);

  return {
    certificateAuthority,
    genericServerPublicParams,
    serverPublicParams,
    serverTrustRoot,
  };
}
