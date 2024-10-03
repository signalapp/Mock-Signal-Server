// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import assert from 'assert';
import Long from 'long';

import { PromiseQueue, assertJsonValue } from '../src/util';

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

      await assert.rejects(
        async () => {
          await q.pushAndWait(23, 10);
        },
        { message: 'PromiseQueue pushAndWait timeout' },
      );
    });

    it('should not timeout on push', async () => {
      const q = new PromiseQueue<number>();

      const push = q.pushAndWait(15, 1000);

      assert.strictEqual(await q.shift(), 15);
      await push;
    });

    it('should timeout on shift', async () => {
      const q = new PromiseQueue<number>();

      await assert.rejects(
        async () => {
          await q.shift(10);
        },
        { message: 'PromiseQueue shift timeout' },
      );
    });

    it('should not timeout on shift', async () => {
      const q = new PromiseQueue<number>();

      const shift = q.shift(1000);

      await q.pushAndWait(17);
      assert.strictEqual(await shift, 17);
    });

    it('should apply default timeouts on push', async () => {
      const q = new PromiseQueue<number>({ timeout: 10 });

      await assert.rejects(
        async () => {
          await q.pushAndWait(23);
        },
        { message: 'PromiseQueue pushAndWait timeout' },
      );
    });

    it('should apply default timeouts on shift', async () => {
      const q = new PromiseQueue<number>({ timeout: 10 });

      await assert.rejects(
        async () => {
          await q.shift();
        },
        { message: 'PromiseQueue shift timeout' },
      );
    });
  });

  describe('assertJsonValue', () => {
    function valid(value: unknown) {
      assert.doesNotThrow(() => assertJsonValue(value));
    }

    function invalid(value: unknown, predicate: RegExp) {
      assert.throws(() => assertJsonValue(value), predicate);
    }

    it('should accept valid json', () => {
      valid(null);
      valid(true);
      valid(false);
      valid(0);
      valid(42);
      valid(-42);
      valid('');
      valid('hi');
      valid([]);
      valid([null, true, 42, 'hi', [1, 2, 3], { a: 'b' }]);
      valid([1, [2, [3, 4], 5], 6]);
      valid({});
      valid({ a: null, b: true, c: 42, d: 'hi', e: [1, 2, 3], f: { a: 'b' } });
      valid({ a: undefined, b: { c: undefined } });
    });

    it('should not accept invalid json', () => {
      invalid(undefined, /value: undefined/);
      invalid(Number.NEGATIVE_INFINITY, /value: -Infinity/);
      invalid(Number.POSITIVE_INFINITY, /value: Infinity/);
      invalid(Number.NaN, /value: NaN/);
      invalid(0n, /value: 0n/);
      invalid(24n, /value: 24n/);
      invalid([undefined], /value\.0: undefined/);
      invalid([1, [42n]], /value\.1\.0: 42n/);
      invalid({ a: 42n }, /value\.a: 42n/);
      invalid({ a: { b: 42n } }, /value\.a\.b: 42n/);
      invalid(() => 'hi', /value: \[Function \(anonymous\)\]/);
      invalid(Buffer.from('hi'), /value: <Buffer 68 69>/);
      invalid(new Uint8Array([68, 69]), /value: Uint8Array\(2\) \[ 68, 69 \]/);
      invalid(class Foo {}, /value: \[class Foo\]/);
      invalid(new (class Foo {})(), /value: Foo {}/);
      invalid(
        Long.fromNumber(42),
        /value: Long { low: 42, high: 0, unsigned: false }/,
      );
    });

    it('should report multiple errors', () => {
      assert.throws(
        () => {
          assertJsonValue({ a: 42n, b: { c: 42n, d: [42n, 42n] } });
        },
        (error) => {
          assert(error instanceof TypeError);
          assert.match(error.message, /value\.a: 42n/);
          assert.match(error.message, /value\.b\.c: 42n/);
          assert.match(error.message, /value\.b\.d\.0: 42n/);
          assert.match(error.message, /value\.b\.d\.1: 42n/);
          return true;
        },
      );
    });
  });
});
