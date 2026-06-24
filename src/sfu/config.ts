// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

export type IpAddress = string & { IpAddress: never };
export type Hostname = string & { Hostname: never };
export type Port = number & { Port: never };

export type MediaPorts = Readonly<{
  udp: Port;
  tcp: Port;
  tls: Port | null;
}>;

export type ServerMediaAddress = Readonly<{
  addresses: ReadonlyArray<IpAddress>;
  ports: MediaPorts;
  hostname: Hostname | null;
}>;
