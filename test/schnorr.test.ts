import { describe, expect, test } from "bun:test";
import { generateKeyPair, sign, verify } from "../src/index";
import { g, modPow, p, q } from "../src/group";

describe("schnorr-lite", () => {
  test("a signature verifies under its own key", () => {
    const keys = generateKeyPair();
    const message = "transfer 100 to alice";
    expect(verify(message, sign(message, keys.privateKey), keys.publicKey)).toBe(
      true
    );
  });

  test("a signature does not verify for another message", () => {
    const keys = generateKeyPair();
    const sig = sign("transfer 100 to alice", keys.privateKey);
    expect(verify("transfer 100 to bob", sig, keys.publicKey)).toBe(false);
  });

  test("a signature does not verify under another key", () => {
    const a = generateKeyPair();
    const b = generateKeyPair();
    const message = "transfer 100 to alice";
    expect(verify(message, sign(message, a.privateKey), b.publicKey)).toBe(
      false
    );
  });

  test("signing is deterministic", () => {
    const keys = generateKeyPair();
    const first = sign("same message", keys.privateKey);
    const second = sign("same message", keys.privateKey);
    expect(first.R).toBe(second.R);
    expect(first.s).toBe(second.s);
  });

  test("keys land in the order-q subgroup", () => {
    const keys = generateKeyPair();
    expect(keys.privateKey > 0n && keys.privateKey < q).toBe(true);
    expect(modPow(keys.publicKey, q, p)).toBe(1n);
  });

  test("a malformed signature is rejected rather than throwing", () => {
    const keys = generateKeyPair();
    expect(verify("m", { R: 0n, s: 1n }, keys.publicKey)).toBe(false);
    expect(verify("m", { R: g, s: q }, keys.publicKey)).toBe(false);
  });
});
