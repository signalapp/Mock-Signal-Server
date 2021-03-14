// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import assert from 'assert';

import { PromiseQueue } from '../src/util';

describe('util', () => {
  describe('PromiseQueue', () => {
    it('should pushAndWait and shift', async () => {
      const q = new PromiseQueue<number>();

      const push = q.pushAndWait(42);

      assert.strictEqual(await q.shift(), 42);
      await push;
    });

    it('should push and shift', async () => {
      const q = new PromiseQueue<number>();

      q.push(42);

      assert.strictEqual(await q.shift(), 42);
    });

    it('should shift and pushAndWait', async () => {
      const q = new PromiseQueue<number>();

      const shift = q.shift();

      await q.pushAndWait(23);

      assert.strictEqual(await shift, 23);
    });

    it('should shift and push', async () => {
      const q = new PromiseQueue<number>();

      const shift = q.shift();

      q.push(23);

      assert.strictEqual(await shift, 23);
    });

    it('should timeout on push', async () => {
      const q = new PromiseQueue<number>();

      await assert.rejects(async () => {
        await q.pushAndWait(23, 10);
      }, { message: 'PromiseQueue pushAndWait timeout' });
    });

    it('should not timeout on push', async () => {
      const q = new PromiseQueue<number>();

      const push = q.pushAndWait(15, 1000);

      assert.strictEqual(await q.shift(), 15);
      await push;
    });

    it('should timeout on shift', async () => {
      const q = new PromiseQueue<number>();

      await assert.rejects(async () => {
        await q.shift(10);
      }, { message: 'PromiseQueue shift timeout' });
    });

    it('should not timeout on shift', async () => {
      const q = new PromiseQueue<number>();

      const shift = q.shift(1000);

      await q.pushAndWait(17);
      assert.strictEqual(await shift, 17);
    });

    it('should apply default timeouts on push', async () => {
      const q = new PromiseQueue<number>({ timeout: 10 });

      await assert.rejects(async () => {
        await q.pushAndWait(23);
      }, { message: 'PromiseQueue pushAndWait timeout' });
    });

    it('should apply default timeouts on shift', async () => {
      const q = new PromiseQueue<number>({ timeout: 10 });

      await assert.rejects(async () => {
        await q.shift();
      }, { message: 'PromiseQueue shift timeout' });
    });
  });
});
